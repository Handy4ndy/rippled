#include <xrpl/tx/transactors/payment/WithdrawAuthorization.h>

#include <xrpl/basics/Log.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/core/ServiceRegistry.h>
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
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFormats.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/Transactor.h>

#include <cstdint>
#include <memory>
#include <optional>

namespace xrpl {

// Returns true when the transaction is a whitelist operation (ttWITHDRAW_PREAUTH),
// false when it is a blacklist operation (ttWITHDRAW_NOAUTH).
static bool
isWhitelist(STTx const& tx)
{
    return tx.getTxnType() == ttWITHDRAW_PREAUTH;
}

// ---------------------------------------------------------------------------
// preflight
// ---------------------------------------------------------------------------

NotTEC
WithdrawAuthorization::preflight(PreflightContext const& ctx)
{

    auto const optAuth = ctx.tx[~sfAuthorize];
    auto const optUnauth = ctx.tx[~sfUnauthorize];
    int const authPresent =
        static_cast<int>(optAuth.has_value()) + static_cast<int>(optUnauth.has_value());

    if (authPresent != 1)
    {
        JLOG(ctx.j.trace()) << "Malformed transaction: "
                               "Invalid Authorize and Unauthorize field combination.";
        return temMALFORMED;
    }

    // NOLINTNEXTLINE(bugprone-unchecked-optional-access) authPresent == 1 guarantees one is set
    AccountID const& target(optAuth ? *optAuth : *optUnauth);
    if (!target)
    {
        JLOG(ctx.j.trace()) << "Malformed transaction: Authorized or Unauthorized "
                               "field zeroed.";
        return temINVALID_ACCOUNT_ID;
    }

    if (isWhitelist(ctx.tx))
    {
        // Whitelist: an account may not preauth itself for outgoing payments.
        if (optAuth && (target == ctx.tx[sfAccount]))
        {
            JLOG(ctx.j.trace()) << "Malformed transaction: Attempting to WithdrawPreauth self.";
            return temCANNOT_PREAUTH_SELF;
        }
    }
    else
    {
        // Blacklist: an account may not deny itself outgoing payments.
        if (optUnauth && (target == ctx.tx[sfAccount]))
        {
            JLOG(ctx.j.trace()) << "Malformed transaction: Attempting to WithdrawNoauth self.";
            return temCANNOT_NOAUTH_SELF;
        }
    }

    return tesSUCCESS;
}

// ---------------------------------------------------------------------------
// preclaim
// ---------------------------------------------------------------------------

// DestinationTag for WithdrawPreauth keylet: 0 when absent (XLS-0086).
static std::uint32_t
preauthDestTag(STTx const& tx)
{
    if (auto const opt = tx[~sfDestinationTag])
        return *opt;
    return 0;
}

TER
WithdrawAuthorization::preclaim(PreclaimContext const& ctx)
{
    AccountID const account(ctx.tx[sfAccount]);

    if (isWhitelist(ctx.tx))
    {
        // Whitelist: sfAuthorize = add entry, sfUnauthorize = remove entry.
        // DestinationTag (0 if absent) is part of the keylet.
        auto const tag = preauthDestTag(ctx.tx);
        if (ctx.tx.isFieldPresent(sfAuthorize))
        {
            AccountID const auth{ctx.tx[sfAuthorize]};
            if (!ctx.view.exists(keylet::account(auth)))
                return tecNO_TARGET;

            if (ctx.view.exists(keylet::withdrawPreauth(account, auth, tag)))
                return tecDUPLICATE;
        }
        else if (ctx.tx.isFieldPresent(sfUnauthorize))
        {
            if (!ctx.view.exists(
                    keylet::withdrawPreauth(account, ctx.tx[sfUnauthorize], tag)))
                return tecNO_ENTRY;
        }
    }
    else
    {
        // Blacklist: sfUnauthorize = add entry, sfAuthorize = remove entry.
        if (ctx.tx.isFieldPresent(sfUnauthorize))
        {
            AccountID const unauth{ctx.tx[sfUnauthorize]};
            if (!ctx.view.exists(keylet::account(unauth)))
                return tecNO_TARGET;

            if (ctx.view.exists(keylet::withdrawNoauth(account, unauth)))
                return tecDUPLICATE;

            if (auto const optExp = ctx.tx[~sfExpiration])
            {
                std::uint32_t const closeTime =
                    ctx.view.header().parentCloseTime.time_since_epoch().count();
                if (closeTime >= *optExp)
                {
                    JLOG(ctx.j.trace())
                        << "WithdrawNoauth: Expiration is not after parent close time.";
                    return tecEXPIRED;
                }
            }
        }
        else if (ctx.tx.isFieldPresent(sfAuthorize))
        {
            if (!ctx.view.exists(keylet::withdrawNoauth(account, ctx.tx[sfAuthorize])))
                return tecNO_ENTRY;
        }
    }

    return tesSUCCESS;
}

// ---------------------------------------------------------------------------
// doApply
// ---------------------------------------------------------------------------

TER
WithdrawAuthorization::doApply()
{
    bool const whitelist = isWhitelist(ctx_.tx);

    // Whitelist: sfAuthorize  = add entry, sfUnauthorize = remove entry.
    // Blacklist: sfUnauthorize = add entry, sfAuthorize  = remove entry.
    bool const hasAdd    = ctx_.tx.isFieldPresent(whitelist ? sfAuthorize   : sfUnauthorize);
    bool const hasRemove = ctx_.tx.isFieldPresent(whitelist ? sfUnauthorize : sfAuthorize);

    if (hasAdd)
    {
        auto const sleOwner = view().peek(keylet::account(accountID_));
        if (!sleOwner)
            return {tefINTERNAL};

        auto applyViewContext = ctx_.getApplyViewContext();
        if (auto const ret = checkReserve(
                applyViewContext, sleOwner, preFeeBalance_, {.ownerCountDelta = 1}, j_);
            !isTesSuccess(ret))
            return ret;

        // Use typed field access directly so operator[] compiles.
        AccountID const target =
            whitelist ? ctx_.tx[sfAuthorize] : ctx_.tx[sfUnauthorize];

        std::uint32_t const tag = whitelist ? preauthDestTag(ctx_.tx) : 0;
        Keylet const entryKeylet =
            whitelist ? keylet::withdrawPreauth(accountID_, target, tag)
                      : keylet::withdrawNoauth(accountID_, target);

        auto sleEntry = std::make_shared<SLE>(entryKeylet);
        sleEntry->setAccountID(sfAccount, accountID_);
        if (whitelist)
        {
            sleEntry->setAccountID(sfAuthorize, target);
            // Persist tag when non-zero (keylet always includes the value).
            if (tag != 0)
                sleEntry->setFieldU32(sfDestinationTag, tag);
        }
        else
            sleEntry->setAccountID(sfUnauthorize, target);

        // Only blacklist entries support optional expiration (validated in preclaim).
        if (!whitelist)
        {
            if (auto const optExp = ctx_.tx[~sfExpiration])
                sleEntry->setFieldU32(sfExpiration, *optExp);
        }

        view().insert(sleEntry);

        auto const page = view().dirInsert(
            keylet::ownerDir(accountID_), entryKeylet, describeOwnerDir(accountID_));

        JLOG(j_.trace()) << "Adding "
                         << (whitelist ? "WithdrawPreauth" : "WithdrawNoauth")
                         << " to owner directory "
                         << to_string(entryKeylet.key) << ": "
                         << (page ? "success" : "failure");

        if (!page)
            return tecDIR_FULL;  // LCOV_EXCL_LINE

        sleEntry->setFieldU64(sfOwnerNode, *page);
        increaseOwnerCount(applyViewContext, sleOwner, 1, j_);
        addSponsorToLedgerEntry(applyViewContext, sleEntry);
    }
    else if (hasRemove)
    {
        if (whitelist)
        {
            auto const preauth = keylet::withdrawPreauth(
                accountID_, ctx_.tx[sfUnauthorize], preauthDestTag(ctx_.tx));
            return WithdrawAuthorization::removePreauthFromLedger(view(), preauth.key, j_);
        }
        else
        {
            auto const noauth = keylet::withdrawNoauth(accountID_, ctx_.tx[sfAuthorize]);
            return WithdrawAuthorization::removeNoauthFromLedger(view(), noauth.key, j_);
        }
    }

    return tesSUCCESS;
}

// ---------------------------------------------------------------------------
// removePreauthFromLedger  (used by AccountDelete for ltWITHDRAW_PREAUTH)
// ---------------------------------------------------------------------------

TER
WithdrawAuthorization::removePreauthFromLedger(
    ApplyView& view,
    uint256 const& preauthIndex,
    beast::Journal j)
{
    auto const slePreauth{view.peek(keylet::withdrawPreauth(preauthIndex))};
    if (!slePreauth)
    {
        JLOG(j.warn()) << "Selected WithdrawPreauth does not exist.";
        return tecNO_ENTRY;
    }

    AccountID const account{(*slePreauth)[sfAccount]};
    std::uint64_t const page{(*slePreauth)[sfOwnerNode]};
    if (!view.dirRemove(keylet::ownerDir(account), page, preauthIndex, false))
    {
        // LCOV_EXCL_START
        JLOG(j.fatal()) << "Unable to delete WithdrawPreauth from owner.";
        return tefBAD_LEDGER;
        // LCOV_EXCL_STOP
    }

    auto const sleOwner = view.peek(keylet::account(account));
    if (!sleOwner)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    decreaseOwnerCountForObject(view, sleOwner, slePreauth, 1, j);
    view.erase(slePreauth);

    return tesSUCCESS;
}

// ---------------------------------------------------------------------------
// removeNoauthFromLedger  (used by AccountDelete for ltWITHDRAW_NOAUTH)
// ---------------------------------------------------------------------------

TER
WithdrawAuthorization::removeNoauthFromLedger(
    ApplyView& view,
    uint256 const& noauthIndex,
    beast::Journal j)
{
    auto const sleNoauth{view.peek(keylet::withdrawNoauth(noauthIndex))};
    if (!sleNoauth)
    {
        JLOG(j.warn()) << "Selected WithdrawNoauth does not exist.";
        return tecNO_ENTRY;
    }

    AccountID const account{(*sleNoauth)[sfAccount]};
    std::uint64_t const page{(*sleNoauth)[sfOwnerNode]};
    if (!view.dirRemove(keylet::ownerDir(account), page, noauthIndex, false))
    {
        // LCOV_EXCL_START
        JLOG(j.fatal()) << "Unable to delete WithdrawNoauth from owner.";
        return tefBAD_LEDGER;
        // LCOV_EXCL_STOP
    }

    auto const sleOwner = view.peek(keylet::account(account));
    if (!sleOwner)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    decreaseOwnerCountForObject(view, sleOwner, sleNoauth, 1, j);
    view.erase(sleNoauth);

    return tesSUCCESS;
}

// ---------------------------------------------------------------------------
// Invariant stubs
// ---------------------------------------------------------------------------

void
WithdrawAuthorization::visitInvariantEntry(
    bool, SLE::ConstRef, SLE::ConstRef)
{
}

bool
WithdrawAuthorization::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
