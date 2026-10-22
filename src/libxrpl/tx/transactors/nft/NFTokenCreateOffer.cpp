#include <xrpl/tx/transactors/nft/NFTokenCreateOffer.h>

#include <xrpl/basics/base_uint.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/ledger/View.h>
#include <xrpl/ledger/helpers/CredentialHelpers.h>
#include <xrpl/ledger/helpers/NFTokenHelpers.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STAccount.h>  // IWYU pragma: keep
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/protocol/nft.h>
#include <xrpl/tx/Transactor.h>

#include <cstdint>
namespace xrpl {

std::uint32_t
NFTokenCreateOffer::getFlagsMask(PreflightContext const& ctx)
{
    return tfNFTokenCreateOfferMask;
}

NotTEC
NFTokenCreateOffer::preflight(PreflightContext const& ctx)
{
    auto const txFlags = ctx.tx.getFlags();

    auto const nftFlags = nft::getFlags(ctx.tx[sfNFTokenID]);

    // Use implementation shared with NFTokenMint
    if (NotTEC notTec = nft::tokenOfferCreatePreflight(
            ctx.tx[sfAccount],
            ctx.tx[sfAmount],
            ctx.tx[~sfDestination],
            ctx.tx[~sfExpiration],
            nftFlags,
            ctx.rules,
            ctx.tx[~sfOwner],
            txFlags);
        !isTesSuccess(notTec))
        return notTec;

    return tesSUCCESS;
}

TER
NFTokenCreateOffer::preclaim(PreclaimContext const& ctx)
{
    if (hasExpired(ctx.view, ctx.tx[~sfExpiration]))
        return tecEXPIRED;

    if (!ctx.tx.isFieldPresent(sfDestination))
    {
        auto const account = ctx.tx[sfAccount];
        if (auto const sleSrc = ctx.view.read(keylet::account(account)))
        {
            if (auto err = verifyUncontrolledValueExit(ctx.view, account, sleSrc, ctx.j);
                !isTesSuccess(err))
                return err;
        }
    }

    UInt256 const nftokenID = ctx.tx[sfNFTokenID];
    std::uint32_t const txFlags = ctx.tx.getFlags();
    if (!nft::findToken(
            ctx.view, ctx.tx[ctx.tx.isFlag(tfSellNFToken) ? sfAccount : sfOwner], nftokenID))
        return tecNO_ENTRY;

    // Use implementation shared with NFTokenMint
    return nft::tokenOfferCreatePreclaim(
        ctx.view,
        ctx.tx[sfAccount],
        nft::getIssuer(nftokenID),
        ctx.tx[sfAmount],
        ctx.tx[~sfDestination],
        nft::getFlags(nftokenID),
        nft::getTransferFee(nftokenID),
        ctx.j,
        ctx.tx[~sfOwner],
        txFlags);
}

TER
NFTokenCreateOffer::doApply()
{
    AccountID const account = ctx_.tx[sfAccount];
    // Directed create: WithdrawAuth gates seller/buyer -> Destination.
    // Buy offers also deposit-check Destination (funds may settle that way).
    // Directed sell: NFT leaves the seller to Destination on accept; soft W
    // mirrors Firewall check-class dest preauth. Open sell uses U-exit in
    // preclaim instead.
    if (auto const dest = ctx_.tx[~sfDestination])
    {
        auto const sleSrc = view().read(keylet::account(account));
        if (auto err = verifyWithdrawAuth(view(), ctx_.tx, account, *dest, sleSrc, j_, 0);
            !isTesSuccess(err))
            return err;
        if (!ctx_.tx.isFlag(tfSellNFToken))
        {
            auto const sleDst = view().read(keylet::account(*dest));
            if (auto err = verifyDepositPreauth(ctx_.tx, view(), account, *dest, sleDst, j_);
                !isTesSuccess(err))
                return err;
        }
    }

    // Use implementation shared with NFTokenMint
    return nft::tokenOfferCreateApply(
        view(),
        ctx_.tx[sfAccount],
        ctx_.tx[sfAmount],
        ctx_.tx[~sfDestination],
        ctx_.tx[~sfExpiration],
        ctx_.tx.getSeqProxy(),
        ctx_.tx[sfNFTokenID],
        preFeeBalance_,
        j_,
        ctx_.tx.getFlags());
}

void
NFTokenCreateOffer::visitInvariantEntry(bool, SLE::ConstRef, SLE::ConstRef)
{
    // No transaction-specific invariants yet (future work).
}

bool
NFTokenCreateOffer::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    // No transaction-specific invariants yet (future work).
    return true;
}

}  // namespace xrpl
