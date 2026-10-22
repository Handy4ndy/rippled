#include <xrpl/tx/transactors/payment/WithdrawSetauth.h>

#include <xrpl/basics/Log.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/ledger/helpers/AccountRootHelpers.h>
#include <xrpl/ledger/helpers/DirectoryHelpers.h>
#include <xrpl/ledger/helpers/SponsorHelpers.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/Keylet.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/STArray.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STObject.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/Transactor.h>

#include <cstdint>
#include <memory>
#include <set>

namespace xrpl {

std::uint32_t
WithdrawSetauth::getFlagsMask(PreflightContext const& /*ctx*/)
{
    return tfWithdrawSetauthMask;
}

NotTEC
WithdrawSetauth::preflight(PreflightContext const& ctx)
{

    auto const flags = ctx.tx.getFlags();
    bool const setNoauth = (flags & tfSetNoauthList) != 0;
    bool const setPreauth = (flags & tfSetPreauthList) != 0;

    if (setNoauth == setPreauth)
    {
        JLOG(ctx.j.trace()) << "WithdrawSetauth: exactly one of tfSetNoauthList/"
                               "tfSetPreauthList must be set.";
        return temINVALID_FLAG;
    }

    if (!ctx.tx.isFieldPresent(sfProviders))
        return tesSUCCESS;

    auto const& providers = ctx.tx.getFieldArray(sfProviders);
    if (providers.empty())
        return tesSUCCESS;

    if (providers.size() > maxAuthProvidersArraySize)
    {
        JLOG(ctx.j.trace()) << "WithdrawSetauth: Providers array too large.";
        return temMALFORMED;
    }

    AccountID const account = ctx.tx.getAccountID(sfAccount);
    std::set<AccountID> seen;

    for (auto const& entry : providers)
    {
        AccountID const provider = entry.getAccountID(sfAccount);
        if (!provider)
        {
            JLOG(ctx.j.trace()) << "WithdrawSetauth: provider AccountID is zero.";
            return temINVALID_ACCOUNT_ID;
        }
        if (provider == account)
        {
            JLOG(ctx.j.trace()) << "WithdrawSetauth: account may not subscribe to itself.";
            if (setPreauth)
                return temCANNOT_PREAUTH_SELF;
            return temCANNOT_NOAUTH_SELF;
        }
        if (!seen.emplace(provider).second)
        {
            JLOG(ctx.j.trace()) << "WithdrawSetauth: duplicate provider in sfProviders.";
            return temMALFORMED;
        }
    }

    return tesSUCCESS;
}

TER
WithdrawSetauth::preclaim(PreclaimContext const& ctx)
{
    AccountID const account = ctx.tx.getAccountID(sfAccount);

    if (!ctx.view.exists(keylet::account(account)))
        return tefINTERNAL;  // LCOV_EXCL_LINE


    auto const flags = ctx.tx.getFlags();
    Keylet const targetKeylet = (flags & tfSetNoauthList)
        ? keylet::withdrawSetNoauth(account)
        : keylet::withdrawSetPreauth(account);

    bool const hasProviders = ctx.tx.isFieldPresent(sfProviders) &&
        !ctx.tx.getFieldArray(sfProviders).empty();

    if (!hasProviders)
    {
        if (!ctx.view.exists(targetKeylet))
            return tecNO_ENTRY;
        return tesSUCCESS;
    }

    for (auto const& entry : ctx.tx.getFieldArray(sfProviders))
    {
        AccountID const provider = entry.getAccountID(sfAccount);
        if (!ctx.view.exists(keylet::account(provider)))
            return tecNO_TARGET;
    }

    return tesSUCCESS;
}

TER
WithdrawSetauth::doApply()
{
    auto const flags = ctx_.tx.getFlags();
    Keylet const targetKeylet = (flags & tfSetNoauthList)
        ? keylet::withdrawSetNoauth(accountID_)
        : keylet::withdrawSetPreauth(accountID_);

    bool const hasProviders = ctx_.tx.isFieldPresent(sfProviders) &&
        !ctx_.tx.getFieldArray(sfProviders).empty();

    if (!hasProviders)
    {
        return (flags & tfSetNoauthList)
            ? removeSetNoauthFromLedger(view(), targetKeylet.key, j_)
            : removeSetPreauthFromLedger(view(), targetKeylet.key, j_);
    }

    auto const& txProviders = ctx_.tx.getFieldArray(sfProviders);
    std::set<AccountID> providerSet;
    for (auto const& entry : txProviders)
        providerSet.emplace(entry.getAccountID(sfAccount));

    STArray sortedProviders(sfProviders, providerSet.size());
    for (auto const& providerId : providerSet)
    {
        auto obj = STObject::makeInnerObject(sfDepositProvider);
        obj.setAccountID(sfAccount, providerId);
        sortedProviders.push_back(std::move(obj));
    }

    if (auto const sleSLE = view().peek(targetKeylet))
    {
        sleSLE->peekFieldArray(sfProviders) = std::move(sortedProviders);
        view().update(sleSLE);
        return tesSUCCESS;
    }

    auto const sleOwner = view().peek(keylet::account(accountID_));
    if (!sleOwner)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    auto applyViewContext = ctx_.getApplyViewContext();
    if (auto const ret = checkReserve(
            applyViewContext, sleOwner, preFeeBalance_, {.ownerCountDelta = 1}, j_);
        !isTesSuccess(ret))
        return ret;

    auto sleDst = std::make_shared<SLE>(targetKeylet);
    sleDst->setAccountID(sfAccount, accountID_);
    sleDst->peekFieldArray(sfProviders) = std::move(sortedProviders);

    auto const page =
        view().dirInsert(keylet::ownerDir(accountID_), targetKeylet, describeOwnerDir(accountID_));

    if (!page)
        return tecDIR_FULL;  // LCOV_EXCL_LINE

    sleDst->setFieldU64(sfOwnerNode, *page);
    view().insert(sleDst);
    increaseOwnerCount(applyViewContext, sleOwner, 1, j_);
    addSponsorToLedgerEntry(applyViewContext, sleDst);

    return tesSUCCESS;
}

TER
WithdrawSetauth::removeSetNoauthFromLedger(
    ApplyView& view,
    uint256 const& index,
    beast::Journal j)
{
    auto const sle = view.peek(keylet::withdrawSetNoauth(index));
    if (!sle)
    {
        JLOG(j.warn()) << "Selected WithdrawSetNoauth does not exist.";
        return tecNO_ENTRY;
    }

    AccountID const account{(*sle)[sfAccount]};
    std::uint64_t const page{(*sle)[sfOwnerNode]};

    if (!view.dirRemove(keylet::ownerDir(account), page, index, false))
    {
        // LCOV_EXCL_START
        JLOG(j.fatal()) << "Unable to delete WithdrawSetNoauth from owner.";
        return tefBAD_LEDGER;
        // LCOV_EXCL_STOP
    }

    auto const sleOwner = view.peek(keylet::account(account));
    if (!sleOwner)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    decreaseOwnerCountForObject(view, sleOwner, sle, 1, j);
    view.erase(sle);
    return tesSUCCESS;
}

TER
WithdrawSetauth::removeSetPreauthFromLedger(
    ApplyView& view,
    uint256 const& index,
    beast::Journal j)
{
    auto const sle = view.peek(keylet::withdrawSetPreauth(index));
    if (!sle)
    {
        JLOG(j.warn()) << "Selected WithdrawSetPreauth does not exist.";
        return tecNO_ENTRY;
    }

    AccountID const account{(*sle)[sfAccount]};
    std::uint64_t const page{(*sle)[sfOwnerNode]};

    if (!view.dirRemove(keylet::ownerDir(account), page, index, false))
    {
        // LCOV_EXCL_START
        JLOG(j.fatal()) << "Unable to delete WithdrawSetPreauth from owner.";
        return tefBAD_LEDGER;
        // LCOV_EXCL_STOP
    }

    auto const sleOwner = view.peek(keylet::account(account));
    if (!sleOwner)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    decreaseOwnerCountForObject(view, sleOwner, sle, 1, j);
    view.erase(sle);
    return tesSUCCESS;
}

void
WithdrawSetauth::visitInvariantEntry(
    bool, SLE::ConstRef, SLE::ConstRef)
{
}

bool
WithdrawSetauth::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
