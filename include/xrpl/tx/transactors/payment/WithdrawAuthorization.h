#pragma once

#include <xrpl/basics/base_uint.h>
#include <xrpl/beast/utility/Journal.h>
#include <xrpl/ledger/ApplyView.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/ApplyContext.h>
#include <xrpl/tx/Transactor.h>

namespace xrpl {

/// Handles both ttWITHDRAW_PREAUTH (outgoing whitelist) and
/// ttWITHDRAW_NOAUTH (outgoing blacklist) transactions in a single transactor.
/// The active mode is determined at runtime via getTxnType().
class WithdrawAuthorization : public Transactor
{
public:
    static constexpr auto kConsequencesFactory = ConsequencesFactoryType::Normal;

    explicit WithdrawAuthorization(ApplyContext& ctx) : Transactor(ctx)
    {
    }

    static NotTEC
    preflight(PreflightContext const& ctx);

    static TER
    preclaim(PreclaimContext const& ctx);

    TER
    doApply() override;

    void
    visitInvariantEntry(bool isDelete, SLE::ConstRef before, SLE::ConstRef after) override;

    [[nodiscard]] bool
    finalizeInvariants(
        STTx const& tx,
        TER result,
        XRPAmount fee,
        ReadView const& view,
        beast::Journal const& j) override;

    // Interface used by AccountDelete — one per SLE type so the
    // nonObligationDeleter switch can route ltWITHDRAW_PREAUTH and
    // ltWITHDRAW_NOAUTH independently.
    static TER
    removePreauthFromLedger(ApplyView& view, uint256 const& delIndex, beast::Journal j);

    static TER
    removeNoauthFromLedger(ApplyView& view, uint256 const& delIndex, beast::Journal j);
};

}  // namespace xrpl
