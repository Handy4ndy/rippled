#include <xrpl/tx/transactors/payment/FirewallSet.h>

#include <xrpl/basics/Log.h>
#include <xrpl/beast/utility/Zero.h>
#include <xrpl/ledger/helpers/AccountRootHelpers.h>
#include <xrpl/ledger/helpers/DirectoryHelpers.h>
#include <xrpl/ledger/helpers/PaymentPolicyHelpers.h>
#include <xrpl/ledger/helpers/SponsorHelpers.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/tx/Transactor.h>

#include <memory>

namespace xrpl {

NotTEC
FirewallSet::preflight(PreflightContext const& ctx)
{
    if (!ctx.rules.enabled(featureFirewall))
        return temDISABLED;
    // Firewall create/update depends on WithdrawAuth and withdraw objects.
    if (!ctx.rules.enabled(featurePaymentPolicy))
        return temDISABLED;

    bool const isUpdate = ctx.tx.isFieldPresent(sfFirewallID);

    if (isUpdate)
    {
        if (ctx.tx.isFieldPresent(sfBackup))
            return temMALFORMED;
    }
    else
    {
        if (!ctx.tx.isFieldPresent(sfCounterparty) || !ctx.tx.isFieldPresent(sfBackup))
            return temMALFORMED;
        if (ctx.tx.isFieldPresent(sfCounterpartySignature))
            return temMALFORMED;
        if (!ctx.tx.isFieldPresent(sfMaxFee))
            return temMALFORMED;

        AccountID const account = ctx.tx.getAccountID(sfAccount);
        AccountID const cp = ctx.tx.getAccountID(sfCounterparty);
        AccountID const backup = ctx.tx.getAccountID(sfBackup);
        if (!cp || !backup || cp == account || backup == account)
            return temMALFORMED;

        auto const maxFee = ctx.tx.getFieldAmount(sfMaxFee);
        if (!maxFee.native() || maxFee.xrp() <= beast::kZero)
            return temMALFORMED;
    }

    if (ctx.tx.isFieldPresent(sfCounterparty))
    {
        AccountID const cp = ctx.tx.getAccountID(sfCounterparty);
        if (!cp || cp == ctx.tx.getAccountID(sfAccount))
            return temMALFORMED;
    }

    if (ctx.tx.isFieldPresent(sfMaxFee))
    {
        auto const maxFee = ctx.tx.getFieldAmount(sfMaxFee);
        if (!maxFee.native())
            return temMALFORMED;
    }

    if (ctx.tx.isFieldPresent(sfMaxAmount))
    {
        auto const maxAmt = ctx.tx.getFieldAmount(sfMaxAmount);
        if (!maxAmt.native() || maxAmt.xrp() < beast::kZero)
            return temMALFORMED;
        if (!isUpdate && maxAmt.xrp() == beast::kZero)
            return temMALFORMED;
    }

    return tesSUCCESS;
}

TER
FirewallSet::preclaim(PreclaimContext const& ctx)
{
    AccountID const account = ctx.tx.getAccountID(sfAccount);
    auto const fwKey = keylet::firewall(account);
    bool const isUpdate = ctx.tx.isFieldPresent(sfFirewallID);

    if (isUpdate)
    {
        auto const sleFw = ctx.view.read(fwKey);
        if (!sleFw)
            return tecNO_TARGET;
        if (ctx.tx.getFieldH256(sfFirewallID) != fwKey.key)
            return tecNO_TARGET;
        if ((*sleFw)[sfOwner] != account)
            return tecNO_PERMISSION;

        AccountID const cp = (*sleFw)[sfCounterparty];
        if (auto const ter = verifyCounterpartyCosign(ctx.view, ctx.tx, cp, ctx.j);
            !isTesSuccess(ter))
            return ter;

        if (ctx.tx.isFieldPresent(sfCounterparty))
        {
            AccountID const newCp = ctx.tx.getAccountID(sfCounterparty);
            if (!ctx.view.exists(keylet::account(newCp)))
                return tecNO_DST;
            if (newCp == cp)
                return tecDUPLICATE;
        }
    }
    else
    {
        if (ctx.view.exists(fwKey))
            return tecDUPLICATE;

        auto const sleAcct = ctx.view.read(keylet::account(account));
        if (!sleAcct)
            return terNO_ACCOUNT;  // LCOV_EXCL_LINE
        if ((sleAcct->getFlags() & lsfWithdrawAuth) == 0u)
        {
            JLOG(ctx.j.trace()) << "FirewallSet create requires asfWithdrawAuth (lsfWithdrawAuth)";
            return tecREQUIRES_FLAG;
        }

        AccountID const cp = ctx.tx.getAccountID(sfCounterparty);
        AccountID const backup = ctx.tx.getAccountID(sfBackup);
        if (!ctx.view.exists(keylet::account(cp)))
            return tecNO_DST;
        if (!ctx.view.exists(keylet::account(backup)))
            return tecNO_DST;

        // An existing backup WithdrawPreauth is reused in doApply (soft
        // FirewallDelete leaves it; users may also have preauthorized backup
        // before create). Do not treat that as tecDUPLICATE.
    }

    return tesSUCCESS;
}

TER
FirewallSet::doApply()
{
    auto const fwKey = keylet::firewall(accountID_);
    bool const isUpdate = ctx_.tx.isFieldPresent(sfFirewallID);

    if (isUpdate)
    {
        auto sleFw = view().peek(fwKey);
        if (!sleFw)
            return tecNO_TARGET;  // LCOV_EXCL_LINE

        if (ctx_.tx.isFieldPresent(sfCounterparty))
            sleFw->setAccountID(sfCounterparty, ctx_.tx.getAccountID(sfCounterparty));

        if (ctx_.tx.isFieldPresent(sfMaxFee))
        {
            auto const maxFee = ctx_.tx.getFieldAmount(sfMaxFee);
            if (maxFee.xrp() == beast::kZero)
                sleFw->makeFieldAbsent(sfMaxFee);
            else
                sleFw->setFieldAmount(sfMaxFee, maxFee);
        }

        if (ctx_.tx.isFieldPresent(sfMaxAmount))
        {
            auto const maxAmt = ctx_.tx.getFieldAmount(sfMaxAmount);
            if (maxAmt.xrp() == beast::kZero)
            {
                sleFw->makeFieldAbsent(sfMaxAmount);
                sleFw->makeFieldAbsent(sfTransferredAmount);
                sleFw->makeFieldAbsent(sfPeriodStart);
            }
            else
                sleFw->setFieldAmount(sfMaxAmount, maxAmt);
        }

        view().update(sleFw);
        return tesSUCCESS;
    }

    auto const sleOwner = view().peek(keylet::account(accountID_));
    if (!sleOwner)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    AccountID const cp = ctx_.tx.getAccountID(sfCounterparty);
    AccountID const backup = ctx_.tx.getAccountID(sfBackup);
    std::uint32_t const tag = ctx_.tx[~sfDestinationTag].value_or(0);
    auto const preKey = keylet::withdrawPreauth(accountID_, backup, tag);
    bool const needBackupPreauth = !view().exists(preKey);

    auto applyViewContext = ctx_.getApplyViewContext();
    std::int32_t const ownerDelta = needBackupPreauth ? 2 : 1;
    if (auto const ret = checkReserve(
            applyViewContext, sleOwner, preFeeBalance_, {.ownerCountDelta = ownerDelta}, j_);
        !isTesSuccess(ret))
        return ret;

    auto sleFw = std::make_shared<SLE>(fwKey);
    sleFw->setAccountID(sfOwner, accountID_);
    sleFw->setAccountID(sfCounterparty, cp);
    sleFw->setFieldAmount(sfMaxFee, ctx_.tx.getFieldAmount(sfMaxFee));
    if (ctx_.tx.isFieldPresent(sfMaxAmount))
        sleFw->setFieldAmount(sfMaxAmount, ctx_.tx.getFieldAmount(sfMaxAmount));

    view().insert(sleFw);
    auto const page =
        view().dirInsert(keylet::ownerDir(accountID_), fwKey, describeOwnerDir(accountID_));
    if (!page)
        return tecDIR_FULL;  // LCOV_EXCL_LINE

    sleFw->setFieldU64(sfOwnerNode, *page);
    increaseOwnerCount(applyViewContext, sleOwner, 1, j_);
    addSponsorToLedgerEntry(applyViewContext, sleFw);

    // FirewallDelete without tfClearWithdrawLists leaves the backup preauth.
    // Re-create must reuse that entry instead of failing with tecDUPLICATE.
    if (needBackupPreauth)
    {
        auto slePre = std::make_shared<SLE>(preKey);
        slePre->setAccountID(sfAccount, accountID_);
        slePre->setAccountID(sfAuthorize, backup);
        if (tag != 0)
            slePre->setFieldU32(sfDestinationTag, tag);

        view().insert(slePre);
        auto const page2 =
            view().dirInsert(keylet::ownerDir(accountID_), preKey, describeOwnerDir(accountID_));
        if (!page2)
            return tecDIR_FULL;  // LCOV_EXCL_LINE

        slePre->setFieldU64(sfOwnerNode, *page2);
        increaseOwnerCount(applyViewContext, sleOwner, 1, j_);
        addSponsorToLedgerEntry(applyViewContext, slePre);
    }

    return tesSUCCESS;
}

void
FirewallSet::visitInvariantEntry(bool, SLE::ConstRef, SLE::ConstRef)
{
}

bool
FirewallSet::finalizeInvariants(STTx const&, TER, XRPAmount, ReadView const&, beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
