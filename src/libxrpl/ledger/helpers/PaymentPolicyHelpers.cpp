#include <xrpl/ledger/helpers/PaymentPolicyHelpers.h>

#include <xrpl/basics/Log.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/beast/utility/Zero.h>
#include <xrpl/ledger/ApplyView.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/ledger/helpers/CredentialHelpers.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/HashPrefix.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/STArray.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STObject.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/SeqProxy.h>
#include <xrpl/protocol/Serializer.h>
#include <xrpl/protocol/Sign.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/digest.h>

#include <memory>

namespace xrpl {

FirewallAction
firewallActionFor(TxType tt)
{
    switch (tt)
    {
        // Directed value transfers: WithdrawPreauth dest -> seed OK; else CP.
        case ttPAYMENT:
        case ttESCROW_CREATE:
        case ttESCROW_FINISH:
        case ttPAYCHAN_CREATE:
        case ttPAYCHAN_FUND:
        case ttPAYCHAN_CLAIM:
        case ttCHECK_CREATE:
        case ttCHECK_CASH:
        case ttNFTOKEN_MINT:
        case ttNFTOKEN_CREATE_OFFER:
        case ttNFTOKEN_ACCEPT_OFFER:
        case ttCONFIDENTIAL_MPT_SEND:
        case ttVAULT_WITHDRAW:
        case ttLOAN_BROKER_COVER_WITHDRAW:
            return FirewallAction::check;

        // Uncontrolled value exits: always CP while Firewall exists.
        // XChainBridge removed upstream (XRPLF #8255); no ttXCHAIN_* cases.
        case ttOFFER_CREATE:
        case ttAMM_CREATE:
        case ttAMM_DEPOSIT:
        case ttAMM_WITHDRAW:
        case ttAMM_BID:
        case ttVAULT_DEPOSIT:
        case ttLOAN_BROKER_COVER_DEPOSIT:
        case ttLOAN_PAY:
        case ttCONFIDENTIAL_MPT_CONVERT:
        case ttCONFIDENTIAL_MPT_MERGE_INBOX:
        case ttCONFIDENTIAL_MPT_CONVERT_BACK:
        case ttSPONSORSHIP_SET:
        case ttSPONSORSHIP_TRANSFER:
            return FirewallAction::block;

        case ttACCOUNT_DELETE:
        case ttACCOUNT_SET:
        case ttREGULAR_KEY_SET:
        case ttSIGNER_LIST_SET:
        case ttDEPOSIT_PREAUTH:
        case ttDEPOSIT_NOAUTH:
        case ttDEPOSIT_SETAUTH:
        case ttWITHDRAW_PREAUTH:
        case ttWITHDRAW_NOAUTH:
        case ttWITHDRAW_SETAUTH:
        case ttFIREWALL_SET:
        case ttFIREWALL_DELETE:
            return FirewallAction::manage;

        case ttAMENDMENT:
        case ttFEE:
        case ttUNL_MODIFY:
            return FirewallAction::system;

        // Non-value ops: seed-alone. Explicit allow keeps default fail-closed.
        // Batch is allow-class: each inner transaction is classified alone.
        case ttTICKET_CREATE:
        case ttTRUST_SET:
        case ttDELEGATE_SET:
        case ttDID_SET:
        case ttDID_DELETE:
        case ttORACLE_SET:
        case ttORACLE_DELETE:
        case ttNFTOKEN_BURN:
        case ttNFTOKEN_CANCEL_OFFER:
        case ttNFTOKEN_MODIFY:
        case ttOFFER_CANCEL:
        case ttCHECK_CANCEL:
        case ttESCROW_CANCEL:
        case ttCLAWBACK:
        case ttAMM_CLAWBACK:
        case ttAMM_VOTE:
        case ttAMM_DELETE:
        case ttVAULT_CREATE:
        case ttVAULT_SET:
        case ttVAULT_DELETE:
        case ttVAULT_CLAWBACK:
        case ttLOAN_BROKER_SET:
        case ttLOAN_BROKER_DELETE:
        case ttLOAN_BROKER_COVER_CLAWBACK:
        case ttLOAN_SET:
        case ttLOAN_DELETE:
        case ttLOAN_MANAGE:
        case ttCREDENTIAL_CREATE:
        case ttCREDENTIAL_ACCEPT:
        case ttCREDENTIAL_DELETE:
        case ttMPTOKEN_ISSUANCE_CREATE:
        case ttMPTOKEN_ISSUANCE_DESTROY:
        case ttMPTOKEN_ISSUANCE_SET:
        case ttMPTOKEN_AUTHORIZE:
        case ttPERMISSIONED_DOMAIN_SET:
        case ttPERMISSIONED_DOMAIN_DELETE:
        case ttCONFIDENTIAL_MPT_CLAWBACK:
        case ttCONFIDENTIAL_MPT_MIRROR_UPDATE:
        case ttCONFIDENTIAL_MPT_HOLDER_KEY_UPDATE:
        case ttTRANSACTION_PROPOSAL_CREATE:
        case ttTRANSACTION_PROPOSAL_CANCEL:
        case ttLEDGER_STATE_FIX:
        case ttBATCH:
            return FirewallAction::allow;

        default:
            // Fail closed: unknown or future TxTypes require counterparty.
            return FirewallAction::block;
    }
}

bool
isPathingClassPayment(STTx const& tx)
{
    if (tx.getTxnType() != ttPAYMENT)
        return false;
    if (tx.isFieldPresent(sfPaths))
        return true;
    if (tx.isFieldPresent(sfSendMax))
        return true;
    if (tx.isFieldPresent(sfAmount) && !tx.getFieldAmount(sfAmount).native())
        return true;
    return false;
}

DestInfo
extractFirewallDestination(STTx const& tx, ReadView const& view)
{
    DestInfo info;
    auto const tt = tx.getTxnType();

    auto fromTx = [&]() {
        if (tx.isFieldPresent(sfDestination))
        {
            info.destination = tx.getAccountID(sfDestination);
            info.tag = tx[~sfDestinationTag].value_or(0);
            info.hasDestination = true;
        }
    };

    switch (tt)
    {
        case ttPAYMENT:
        case ttESCROW_CREATE:
        case ttPAYCHAN_CREATE:
        case ttCHECK_CREATE:
        case ttACCOUNT_DELETE:
        case ttNFTOKEN_MINT:
        case ttNFTOKEN_CREATE_OFFER:
        case ttCONFIDENTIAL_MPT_SEND:
        case ttVAULT_WITHDRAW:
            fromTx();
            break;

        case ttESCROW_FINISH:
            if (tx.isFieldPresent(sfOwner) && tx.isFieldPresent(sfOfferSequence))
            {
                if (auto const sle = view.read(
                        keylet::escrow(
                            tx.getAccountID(sfOwner),
                            SeqProxy::rawSequence(tx.getFieldU32(sfOfferSequence)))))
                {
                    info.destination = sle->getAccountID(sfDestination);
                    info.tag = sle->isFieldPresent(sfDestinationTag)
                        ? sle->getFieldU32(sfDestinationTag)
                        : 0;
                    info.hasDestination = true;
                }
            }
            break;

        case ttPAYCHAN_CLAIM:
            if (tx.isFieldPresent(sfChannel))
            {
                if (auto const sle = view.read(Keylet{ltPAYCHAN, tx.getFieldH256(sfChannel)}))
                {
                    info.destination = sle->getAccountID(sfDestination);
                    info.tag = sle->isFieldPresent(sfDestinationTag)
                        ? sle->getFieldU32(sfDestinationTag)
                        : 0;
                    info.hasDestination = true;
                }
            }
            break;

        case ttCHECK_CASH:
            // Funds move from the check creator to the casher (tx Account).
            info.destination = tx.getAccountID(sfAccount);
            info.tag = 0;
            info.hasDestination = true;
            break;

        default:
            fromTx();
            break;
    }
    return info;
}

bool
hasFirewall(ReadView const& view, AccountID const& owner)
{
    if (!view.rules().enabled(featureFirewall))
        return false;
    return view.exists(keylet::firewall(owner));
}

AccountID
firewallValueSubject(STTx const& tx, ReadView const& view)
{
    // For pull paths, the Firewall seal binds the account whose funds move,
    // not the submitter (finisher / claimer / casher / NFT accepter).
    auto const tt = tx.getTxnType();
    switch (tt)
    {
        case ttESCROW_FINISH:
            if (tx.isFieldPresent(sfOwner))
                return tx.getAccountID(sfOwner);
            break;

        case ttPAYCHAN_CLAIM:
            if (tx.isFieldPresent(sfChannel))
            {
                if (auto const sle = view.read(Keylet{ltPAYCHAN, tx.getFieldH256(sfChannel)}))
                    return sle->getAccountID(sfAccount);
            }
            break;

        case ttCHECK_CASH:
            if (tx.isFieldPresent(sfCheckID))
            {
                if (auto const sle = view.read(keylet::check(tx.getFieldH256(sfCheckID))))
                    return sle->getAccountID(sfAccount);
            }
            break;

        case ttNFTOKEN_ACCEPT_OFFER: {
            // Buy offer present: funds leave the buy-offer owner.
            // Sell-only accept: the submitter (buyer) pays.
            if (auto const buy = tx[~sfNFTokenBuyOffer])
            {
                if (auto const sle = view.read(keylet::nftokenOffer(*buy)))
                    return sle->getAccountID(sfOwner);
            }
            break;
        }

        default:
            break;
    }

    // Delegated txs: sfDelegate is the signer/fee payer. Funds still leave sfAccount.
    if (tx.isFieldPresent(sfAccount))
        return tx.getAccountID(sfAccount);
    return beast::kZero;
}

TER
verifyCounterpartyCosign(
    ReadView const& view,
    STTx const& tx,
    AccountID const& counterparty,
    beast::Journal j)
{
    if (!tx.isFieldPresent(sfCounterpartySignature))
    {
        JLOG(j.trace()) << "Firewall: missing CounterpartySignature";
        return tecREQUIRES_COUNTERPARTY;
    }

    auto const& sigObj = tx.getFieldObject(sfCounterpartySignature);
    if (!sigObj.isFieldPresent(sfSigningPubKey) || !sigObj.isFieldPresent(sfTxnSignature))
    {
        JLOG(j.trace()) << "Firewall: CounterpartySignature incomplete";
        return tecREQUIRES_COUNTERPARTY;
    }

    auto const pkBlob = sigObj.getFieldVL(sfSigningPubKey);
    auto const sigBlob = sigObj.getFieldVL(sfTxnSignature);
    if (pkBlob.empty() || sigBlob.empty() || !publicKeyType(makeSlice(pkBlob)))
        return tecREQUIRES_COUNTERPARTY;

    PublicKey const pk(makeSlice(pkBlob));
    AccountID const signerId = calcAccountID(pk);

    auto const sleCp = view.read(keylet::account(counterparty));
    if (!sleCp)
        return tecNO_TARGET;

    bool const masterOk = (signerId == counterparty) && !sleCp->isFlag(lsfDisableMaster);
    bool const regularOk =
        sleCp->isFieldPresent(sfRegularKey) && (sleCp->getAccountID(sfRegularKey) == signerId);
    if (!masterOk && !regularOk)
    {
        JLOG(j.trace()) << "Firewall: cosign key not authorized for counterparty";
        return tecREQUIRES_COUNTERPARTY;
    }

    try
    {
        Serializer data;
        data.add32(signingPrefix(SignatureRole::Counterparty, false, view.rules()));
        tx.addWithoutSigningFields(data);
        if (!verify(pk, data.slice(), makeSlice(sigBlob)))
        {
            JLOG(j.trace()) << "Firewall: CounterpartySignature crypto failed";
            return tecREQUIRES_COUNTERPARTY;
        }
    }
    catch (...)
    {
        return tecREQUIRES_COUNTERPARTY;
    }

    return tesSUCCESS;
}

TER
requireCounterpartyIfFirewalled(
    ReadView const& view,
    STTx const& tx,
    AccountID const& account,
    beast::Journal j)
{
    if (!hasFirewall(view, account))
        return tesSUCCESS;

    auto const sleFw = view.read(keylet::firewall(account));
    if (!sleFw)
        return tesSUCCESS;

    AccountID const cp = sleFw->getAccountID(sfCounterparty);
    return verifyCounterpartyCosign(view, tx, cp, j);
}

bool
accountSetTouchesSealedFlags(STTx const& tx)
{
    if (tx.getTxnType() != ttACCOUNT_SET)
        return false;

    auto touches = [](std::uint32_t flag) {
        return flag == asfDepositAuth || flag == asfDepositNoauth || flag == asfWithdrawAuth ||
            flag == asfWithdrawNoauth;
    };

    if (tx.isFieldPresent(sfSetFlag) && touches(tx.getFieldU32(sfSetFlag)))
        return true;
    if (tx.isFieldPresent(sfClearFlag) && touches(tx.getFieldU32(sfClearFlag)))
        return true;

    return false;
}

bool
accountSetTouchesKeySeal(STTx const& tx)
{
    if (tx.getTxnType() != ttACCOUNT_SET)
        return false;

    if (tx.isFieldPresent(sfSetFlag) && tx.getFieldU32(sfSetFlag) == asfDisableMaster)
        return true;
    if (tx.isFieldPresent(sfClearFlag) && tx.getFieldU32(sfClearFlag) == asfDisableMaster)
        return true;

    return false;
}

XRPAmount
firewallNativeTransfer(STTx const& tx)
{
    auto native = [](STAmount const& a) -> XRPAmount {
        return a.native() ? a.xrp() : XRPAmount{0};
    };

    switch (tx.getTxnType())
    {
        case ttPAYMENT:
            if (tx.isFieldPresent(sfAmount))
            {
                auto const amt = native(tx.getFieldAmount(sfAmount));
                if (amt > beast::kZero)
                    return amt;
            }
            if (tx.isFieldPresent(sfSendMax))
                return native(tx.getFieldAmount(sfSendMax));
            return XRPAmount{0};
        case ttESCROW_CREATE:
        case ttPAYCHAN_CREATE:
        case ttPAYCHAN_FUND:
            if (tx.isFieldPresent(sfAmount))
                return native(tx.getFieldAmount(sfAmount));
            return XRPAmount{0};
        case ttCHECK_CREATE:
            if (tx.isFieldPresent(sfSendMax))
                return native(tx.getFieldAmount(sfSendMax));
            return XRPAmount{0};
        case ttOFFER_CREATE:
            if (tx.isFieldPresent(sfTakerGets))
                return native(tx.getFieldAmount(sfTakerGets));
            return XRPAmount{0};
        default:
            return XRPAmount{0};
    }
}

namespace {

constexpr std::uint32_t kFirewallAmountPeriodSeconds = 24 * 60 * 60;

XRPAmount
periodSpent(ReadView const& view, SLE const& sleFw)
{
    if (!sleFw.isFieldPresent(sfPeriodStart) || !sleFw.isFieldPresent(sfTransferredAmount))
        return XRPAmount{0};

    auto const now = view.header().parentCloseTime.time_since_epoch().count();
    auto const start = sleFw.getFieldU32(sfPeriodStart);
    if (now >= start + kFirewallAmountPeriodSeconds)
        return XRPAmount{0};

    auto const tr = sleFw.getFieldAmount(sfTransferredAmount);
    return tr.native() ? tr.xrp() : XRPAmount{0};
}

TER
checkFirewallMaxAmount(
    ReadView const& view,
    STTx const& tx,
    std::shared_ptr<SLE const> const& sleFw,
    beast::Journal j)
{
    if (!sleFw->isFieldPresent(sfMaxAmount))
        return tesSUCCESS;

    auto const cap = sleFw->getFieldAmount(sfMaxAmount);
    if (!cap.native())
        return tesSUCCESS;

    auto const amt = firewallNativeTransfer(tx);
    if (amt <= beast::kZero)
        return tesSUCCESS;

    if (periodSpent(view, *sleFw) + amt > cap.xrp())
    {
        JLOG(j.trace()) << "Firewall: daily MaxAmount exceeded; CP required";
        AccountID const cp = sleFw->getAccountID(sfCounterparty);
        return verifyCounterpartyCosign(view, tx, cp, j);
    }
    return tesSUCCESS;
}

static bool
withdrawNoauthLive(ReadView const& view, Keylet const& noauthKey)
{
    auto const sleNoauth = view.read(noauthKey);
    if (!sleNoauth)
        return false;
    return !credentials::checkExpired(*sleNoauth, view.header().parentCloseTime);
}

bool
isWithdrawDenied(ReadView const& view, AccountID const& account, AccountID const& destination)
{
    if (withdrawNoauthLive(view, keylet::withdrawNoauth(account, destination)))
        return true;
    if (auto const sleSet = view.read(keylet::withdrawSetNoauth(account)))
    {
        for (auto const& entry : sleSet->getFieldArray(sfProviders))
        {
            if (withdrawNoauthLive(
                    view, keylet::withdrawNoauth(entry.getAccountID(sfAccount), destination)))
                return true;
        }
    }
    return false;
}

bool
isWithdrawPreauthorized(
    ReadView const& view,
    AccountID const& account,
    AccountID const& destination,
    std::uint32_t tag)
{
    if (view.exists(keylet::withdrawPreauth(account, destination, tag)))
        return true;
    if (auto const sleSet = view.read(keylet::withdrawSetPreauth(account)))
    {
        for (auto const& entry : sleSet->getFieldArray(sfProviders))
        {
            if (view.exists(
                    keylet::withdrawPreauth(entry.getAccountID(sfAccount), destination, tag)))
                return true;
        }
    }
    return false;
}

TER
requireFirewallCounterparty(
    ReadView const& view,
    STTx const& tx,
    std::shared_ptr<SLE const> const& sleFw,
    beast::Journal j)
{
    AccountID const cp = sleFw->getAccountID(sfCounterparty);
    return verifyCounterpartyCosign(view, tx, cp, j);
}

}  // namespace

TER
checkFirewall(ReadView const& view, STTx const& tx, beast::Journal j)
{
    if (!view.rules().enabled(featureFirewall))
        return tesSUCCESS;

    AccountID const account = firewallValueSubject(tx, view);
    if (account == beast::kZero)
        return tesSUCCESS;

    auto const tt = tx.getTxnType();
    auto const sleFw = view.read(keylet::firewall(account));

    // Key seal before MaxFee: AccountDelete's base fee is large and would
    // otherwise surface as tefFIREWALL_MAX_FEE instead of tecFIREWALL_ACTIVE.
    if (sleFw && (tt == ttACCOUNT_DELETE || tt == ttREGULAR_KEY_SET || tt == ttSIGNER_LIST_SET))
    {
        JLOG(j.trace()) << "Firewall: key/delete seal active";
        return tecFIREWALL_ACTIVE;
    }

    auto exceedsMaxFee = [&](std::shared_ptr<SLE const> const& sleCap) -> bool {
        if (tt == ttFIREWALL_SET || tt == ttFIREWALL_DELETE)
            return false;
        if (!sleCap || !sleCap->isFieldPresent(sfMaxFee))
            return false;
        auto const maxFee = sleCap->getFieldAmount(sfMaxFee);
        auto const fee = tx.getFieldAmount(sfFee);
        return !fee.native() || !maxFee.native() || fee.xrp() > maxFee.xrp();
    };

    // MaxFee binds whoever actually pays sfFee (delegate on a delegated tx).
    AccountID const feePayer = tx.getFeePayerID();
    if (auto const sleFeeFw = view.read(keylet::firewall(feePayer)); exceedsMaxFee(sleFeeFw))
    {
        JLOG(j.trace()) << "Firewall: fee exceeds MaxFee (fee payer)";
        return tefFIREWALL_MAX_FEE;
    }

    if (!sleFw)
        return tesSUCCESS;

    if (feePayer != account && exceedsMaxFee(sleFw))
    {
        JLOG(j.trace()) << "Firewall: fee exceeds MaxFee (value subject)";
        return tefFIREWALL_MAX_FEE;
    }

    auto const action = firewallActionFor(tt);
    switch (action)
    {
        case FirewallAction::allow:
        case FirewallAction::manage:
        case FirewallAction::system:
            return tesSUCCESS;

        case FirewallAction::block:
            JLOG(j.trace()) << "Firewall: block-class requires counterparty";
            return requireFirewallCounterparty(view, tx, sleFw, j);

        case FirewallAction::check:
            break;
    }

    if (isPathingClassPayment(tx) || tt == ttCONFIDENTIAL_MPT_SEND)
    {
        JLOG(j.trace()) << "Firewall: pathing-class requires counterparty";
        return requireFirewallCounterparty(view, tx, sleFw, j);
    }

    if (tt == ttPAYMENT && tx.isFieldPresent(sfDestination) &&
        tx.getAccountID(sfDestination) == account)
    {
        JLOG(j.trace()) << "Firewall: self-payment requires counterparty";
        return requireFirewallCounterparty(view, tx, sleFw, j);
    }

    auto const dest = extractFirewallDestination(tx, view);
    if (!dest.hasDestination)
    {
        JLOG(j.trace()) << "Firewall: no destination; require counterparty";
        return requireFirewallCounterparty(view, tx, sleFw, j);
    }

    if (isWithdrawDenied(view, account, dest.destination))
    {
        JLOG(j.trace()) << "Firewall: destination on withdraw deny list";
        return tecFIREWALL_BLOCK;
    }

    if (isWithdrawPreauthorized(view, account, dest.destination, dest.tag))
    {
        if (auto const ter = checkFirewallMaxAmount(view, tx, sleFw, j); !isTesSuccess(ter))
            return ter;
        return tesSUCCESS;
    }

    JLOG(j.trace()) << "Firewall: destination not preauthorized; require counterparty";
    return requireFirewallCounterparty(view, tx, sleFw, j);
}

TER
applyFirewallAmountCap(ApplyView& view, STTx const& tx, beast::Journal j)
{
    if (!view.rules().enabled(featureFirewall))
        return tesSUCCESS;

    auto const tt = tx.getTxnType();
    if (tt == ttFIREWALL_SET || tt == ttFIREWALL_DELETE)
        return tesSUCCESS;

    AccountID const account = firewallValueSubject(tx, view);
    if (account == beast::kZero)
        return tesSUCCESS;

    auto sleFw = view.peek(keylet::firewall(account));
    if (!sleFw || !sleFw->isFieldPresent(sfMaxAmount))
        return tesSUCCESS;

    auto const amt = firewallNativeTransfer(tx);
    if (amt <= beast::kZero)
        return tesSUCCESS;

    auto const now =
        static_cast<std::uint32_t>(view.header().parentCloseTime.time_since_epoch().count());
    auto spent = periodSpent(view, *sleFw);
    if (spent == beast::kZero &&
        (!sleFw->isFieldPresent(sfPeriodStart) ||
         now >= sleFw->getFieldU32(sfPeriodStart) + kFirewallAmountPeriodSeconds))
    {
        sleFw->setFieldU32(sfPeriodStart, now);
        spent = XRPAmount{0};
    }

    auto const next = spent + amt;
    sleFw->setFieldAmount(sfTransferredAmount, STAmount{next});
    view.update(sleFw);
    JLOG(j.trace()) << "Firewall: period transferred now " << next;
    return tesSUCCESS;
}

}  // namespace xrpl
