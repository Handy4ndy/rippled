#include <xrpl/tx/transactors/payment/DepositNoauth.h>

#include <xrpl/basics/Log.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/core/ServiceRegistry.h>
#include <xrpl/ledger/helpers/AccountRootHelpers.h>
#include <xrpl/ledger/helpers/CredentialHelpers.h>
#include <xrpl/ledger/helpers/DirectoryHelpers.h>
#include <xrpl/ledger/helpers/PaymentPolicyHelpers.h>
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
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/Transactor.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <utility>

namespace xrpl {

NotTEC
DepositNoauth::preflight(PreflightContext const& ctx)
{
    auto const optAuth = ctx.tx[~sfAuthorize];
    auto const optUnauth = ctx.tx[~sfUnauthorize];
    int const authPresent =
        static_cast<int>(optAuth.has_value()) + static_cast<int>(optUnauth.has_value());

    if (authPresent != 1)
    {
        // There can only be 1 field or the transaction is malformed.
        JLOG(ctx.j.trace()) << "Malformed transaction: "
                               "Invalid Authorize and Unauthorize field combination.";
        return temMALFORMED;
    }

    // Make sure that the passed account is valid.
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access) authPresent == 1 guarantees one is set
    AccountID const& target(optAuth ? *optAuth : *optUnauth);
    if (!target)
    {
        JLOG(ctx.j.trace()) << "Malformed transaction: Authorized or Unauthorized "
                               "field zeroed.";
        return temINVALID_ACCOUNT_ID;
    }

    // An account may not deny itself.
    if (optUnauth && (target == ctx.tx[sfAccount]))
    {
        JLOG(ctx.j.trace()) << "Malformed transaction: Attempting to DepositNoauth self.";
        return temCANNOT_NOAUTH_SELF;
    }

    return tesSUCCESS;
}

TER
DepositNoauth::preclaim(PreclaimContext const& ctx)
{
    AccountID const account(ctx.tx[sfAccount]);

    if (auto const ter = requireCounterpartyIfFirewalled(ctx.view, ctx.tx, account, ctx.j);
        !isTesSuccess(ter))
        return ter;

    // Determine which operation we're performing: authorizing or unauthorizing.
    if (ctx.tx.isFieldPresent(sfUnauthorize))
    {
        // Verify that the Unauthorize account is present in the ledger.
        AccountID const unauth{ctx.tx[sfUnauthorize]};
        if (!ctx.view.exists(keylet::account(unauth)))
            return tecNO_TARGET;

        // Verify that the Noauth entry they asked to add is not already
        // in the ledger.
        if (ctx.view.exists(keylet::depositNoauth(account, unauth)))
            return tecDUPLICATE;

        if (auto const optExp = ctx.tx[~sfExpiration])
        {
            std::uint32_t const closeTime =
                ctx.view.header().parentCloseTime.time_since_epoch().count();
            if (closeTime >= *optExp)
            {
                JLOG(ctx.j.trace()) << "DepositNoauth: Expiration is not after parent close time.";
                return tecEXPIRED;
            }
        }
    }
    else if (ctx.tx.isFieldPresent(sfAuthorize))
    {
        // Verify that the Noauth entry they asked to remove is in the ledger.
        if (!ctx.view.exists(keylet::depositNoauth(account, ctx.tx[sfAuthorize])))
            return tecNO_ENTRY;
    }
    return tesSUCCESS;
}

TER
DepositNoauth::doApply()
{
    if (ctx_.tx.isFieldPresent(sfUnauthorize))
    {
        auto const sleOwner = view().peek(keylet::account(accountID_));
        if (!sleOwner)
            return {tefINTERNAL};

        // A preauth counts against the reserve of the issuing account, but we
        // check the starting balance because we want to allow dipping into the
        // reserve to pay fees.
        auto applyViewContext = ctx_.getApplyViewContext();
        if (auto const ret = checkReserve(
                applyViewContext, sleOwner, preFeeBalance_, {.ownerCountDelta = 1}, j_);
            !isTesSuccess(ret))
            return ret;

        // Preclaim already verified that the Noauth entry does not yet exist.
        // Create and populate the Noauth entry.
        AccountID const unauth{ctx_.tx[sfUnauthorize]};
        Keylet const noauthKeylet = keylet::depositNoauth(accountID_, unauth);
        auto sleNoauth = std::make_shared<SLE>(noauthKeylet);

        sleNoauth->setAccountID(sfAccount, accountID_);
        sleNoauth->setAccountID(sfUnauthorize, unauth);

        if (auto const optExp = ctx_.tx[~sfExpiration])
            sleNoauth->setFieldU32(sfExpiration, *optExp);

        view().insert(sleNoauth);

        auto const page = view().dirInsert(
            keylet::ownerDir(accountID_), noauthKeylet, describeOwnerDir(accountID_));

        JLOG(j_.trace()) << "Adding DepositNoauth to owner directory "
                         << to_string(noauthKeylet.key) << ": " << (page ? "success" : "failure");

        if (!page)
        {
            return tecDIR_FULL;  // LCOV_EXCL_LINE
        }

        sleNoauth->setFieldU64(sfOwnerNode, *page);

        increaseOwnerCount(applyViewContext, sleOwner, 1, j_);
        addSponsorToLedgerEntry(applyViewContext, sleNoauth);
    }
    else if (ctx_.tx.isFieldPresent(sfAuthorize))
    {
        auto const noauth = keylet::depositNoauth(accountID_, ctx_.tx[sfAuthorize]);

        return DepositNoauth::removeFromLedger(view(), noauth.key, j_);
    }
    return tesSUCCESS;
}

TER
DepositNoauth::removeFromLedger(ApplyView& view, uint256 const& noauthIndex, beast::Journal j)
{
    // Existence already checked in preclaim and AccountDelete
    auto const sleNoauth{view.peek(keylet::depositNoauth(noauthIndex))};
    if (!sleNoauth)
    {
        JLOG(j.warn()) << "Selected DepositNoauth does not exist.";
        return tecNO_ENTRY;
    }

    AccountID const account{(*sleNoauth)[sfAccount]};
    std::uint64_t const page{(*sleNoauth)[sfOwnerNode]};
    if (!view.dirRemove(keylet::ownerDir(account), page, noauthIndex, false))
    {
        // LCOV_EXCL_START
        JLOG(j.fatal()) << "Unable to delete DepositNoauth from owner.";
        return tefBAD_LEDGER;
        // LCOV_EXCL_STOP
    }

    // If we succeeded, update the DepositNoauth owner's reserve.
    auto const sleOwner = view.peek(keylet::account(account));
    if (!sleOwner)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    decreaseOwnerCountForObject(view, sleOwner, sleNoauth, 1, j);
    view.erase(sleNoauth);

    return tesSUCCESS;
}

void
DepositNoauth::visitInvariantEntry(bool, SLE::ConstRef, SLE::ConstRef)
{
}

bool
DepositNoauth::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
