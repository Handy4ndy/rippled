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

class DepositSetauth : public Transactor
{
public:
    static constexpr auto kConsequencesFactory = ConsequencesFactoryType::Blocker;

    explicit DepositSetauth(ApplyContext& ctx) : Transactor(ctx)
    {
    }

    static std::uint32_t
    getFlagsMask(PreflightContext const& ctx);

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

    // Removes the DepositSetNoauth SLE for the given index.
    // Used by AccountDelete and the delete path in doApply.
    static TER
    removeSetNoauthFromLedger(ApplyView& view, uint256 const& index, beast::Journal j);

    // Removes the DepositSetPreauth SLE for the given index.
    // Used by AccountDelete and the delete path in doApply.
    static TER
    removeSetPreauthFromLedger(ApplyView& view, uint256 const& index, beast::Journal j);
};

}  // namespace xrpl
