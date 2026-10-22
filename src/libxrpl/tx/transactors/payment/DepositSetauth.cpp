#include <xrpl/tx/transactors/payment/DepositSetauth.h>

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
DepositSetauth::getFlagsMask(PreflightContext const& /*ctx*/)
{
    return tfDepositSetauthMask;
}

NotTEC
DepositSetauth::preflight(PreflightContext const& ctx)
{

    auto const flags = ctx.tx.getFlags();
    bool const setNoauth  = (flags & tfSetNoauthList)  != 0;
    bool const setPreauth = (flags & tfSetPreauthList) != 0;

    // Exactly one list type flag must be set (framework already verified
    // no unknown bits via getFlagsMask; this catches neither-set case).
    if (setNoauth == setPreauth)
    {
        JLOG(ctx.j.trace()) << "DepositSetauth: exactly one of tfSetNoauthList/"
                               "tfSetPreauthList must be set.";
        return temINVALID_FLAG;
    }

    if (!ctx.tx.isFieldPresent(sfProviders))
        return tesSUCCESS;  // absent = delete; nothing further to validate

    auto const& providers = ctx.tx.getFieldArray(sfProviders);
    if (providers.empty())
        return tesSUCCESS;  // empty = delete

    if (providers.size() > maxAuthProvidersArraySize)
    {
        JLOG(ctx.j.trace()) << "DepositSetauth: Providers array too large.";
        return temMALFORMED;
    }

    AccountID const account = ctx.tx.getAccountID(sfAccount);
    std::set<AccountID> seen;

    for (auto const& entry : providers)
    {
        AccountID const provider = entry.getAccountID(sfAccount);
        if (!provider)
        {
            JLOG(ctx.j.trace()) << "DepositSetauth: provider AccountID is zero.";
            return temINVALID_ACCOUNT_ID;
        }
        if (provider == account)
        {
            JLOG(ctx.j.trace()) << "DepositSetauth: account may not subscribe to itself.";
            if (setPreauth)
                return temCANNOT_PREAUTH_SELF;
            return temCANNOT_NOAUTH_SELF;
        }
        if (!seen.emplace(provider).second)
        {
            JLOG(ctx.j.trace()) << "DepositSetauth: duplicate provider in sfProviders.";
            return temMALFORMED;
        }
    }

    return tesSUCCESS;
}

TER
DepositSetauth::preclaim(PreclaimContext const& ctx)
{
    AccountID const account = ctx.tx.getAccountID(sfAccount);

    if (!ctx.view.exists(keylet::account(account)))
        return tefINTERNAL;  // LCOV_EXCL_LINE


    auto const flags = ctx.tx.getFlags();
    Keylet const targetKeylet = (flags & tfSetNoauthList)
        ? keylet::depositSetNoauth(account)
        : keylet::depositSetPreauth(account);

    bool const hasProviders = ctx.tx.isFieldPresent(sfProviders) &&
                              !ctx.tx.getFieldArray(sfProviders).empty();

    if (!hasProviders)
    {
        // Delete path: SLE must already exist.
        if (!ctx.view.exists(targetKeylet))
            return tecNO_ENTRY;
        return tesSUCCESS;
    }

    // Create or replace path: verify each provider account exists on-ledger.
    for (auto const& entry : ctx.tx.getFieldArray(sfProviders))
    {
        AccountID const provider = entry.getAccountID(sfAccount);
        if (!ctx.view.exists(keylet::account(provider)))
            return tecNO_TARGET;
    }

    return tesSUCCESS;
}

TER
DepositSetauth::doApply()
{
    auto const flags = ctx_.tx.getFlags();
    Keylet const targetKeylet = (flags & tfSetNoauthList)
        ? keylet::depositSetNoauth(accountID_)
        : keylet::depositSetPreauth(accountID_);

    bool const hasProviders = ctx_.tx.isFieldPresent(sfProviders) &&
                              !ctx_.tx.getFieldArray(sfProviders).empty();

    if (!hasProviders)
    {
        // Delete path.
        return (flags & tfSetNoauthList)
            ? removeSetNoauthFromLedger(view(), targetKeylet.key, j_)
            : removeSetPreauthFromLedger(view(), targetKeylet.key, j_);
    }

    // Build sorted STArray — use std::set<AccountID> for dedup + ordering.
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
        // Replace path — atomically swap the provider array.
        sleSLE->peekFieldArray(sfProviders) = std::move(sortedProviders);
        view().update(sleSLE);
        return tesSUCCESS;
    }

    // Create path — check reserve, then insert.
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

    JLOG(j_.trace()) << "Adding DepositSetauth SLE to owner directory "
                     << to_string(targetKeylet.key) << ": " << (page ? "success" : "failure");

    if (!page)
        return tecDIR_FULL;  // LCOV_EXCL_LINE

    sleDst->setFieldU64(sfOwnerNode, *page);
    view().insert(sleDst);
    increaseOwnerCount(applyViewContext, sleOwner, 1, j_);
    addSponsorToLedgerEntry(applyViewContext, sleDst);

    return tesSUCCESS;
}

TER
DepositSetauth::removeSetNoauthFromLedger(
    ApplyView& view, uint256 const& index, beast::Journal j)
{
    auto const sle = view.peek(keylet::depositSetNoauth(index));
    if (!sle)
    {
        JLOG(j.warn()) << "Selected DepositSetNoauth does not exist.";
        return tecNO_ENTRY;
    }

    AccountID const account{(*sle)[sfAccount]};
    std::uint64_t const page{(*sle)[sfOwnerNode]};

    if (!view.dirRemove(keylet::ownerDir(account), page, index, false))
    {
        // LCOV_EXCL_START
        JLOG(j.fatal()) << "Unable to delete DepositSetNoauth from owner.";
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
DepositSetauth::removeSetPreauthFromLedger(
    ApplyView& view, uint256 const& index, beast::Journal j)
{
    auto const sle = view.peek(keylet::depositSetPreauth(index));
    if (!sle)
    {
        JLOG(j.warn()) << "Selected DepositSetPreauth does not exist.";
        return tecNO_ENTRY;
    }

    AccountID const account{(*sle)[sfAccount]};
    std::uint64_t const page{(*sle)[sfOwnerNode]};

    if (!view.dirRemove(keylet::ownerDir(account), page, index, false))
    {
        // LCOV_EXCL_START
        JLOG(j.fatal()) << "Unable to delete DepositSetPreauth from owner.";
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
DepositSetauth::visitInvariantEntry(
    bool, SLE::ConstRef, SLE::ConstRef)
{
}

bool
DepositSetauth::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
