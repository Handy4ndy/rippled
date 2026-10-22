#include <xrpl/ledger/helpers/CredentialHelpers.h>

#include <xrpl/basics/Log.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/basics/chrono.h>
#include <xrpl/beast/utility/Journal.h>
#include <xrpl/ledger/ApplyView.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/ledger/entries/DepositPreauthEntry.h>
#include <xrpl/ledger/helpers/AccountRootHelpers.h>
#include <xrpl/ledger/helpers/DirectoryHelpers.h>
#include <xrpl/ledger/helpers/PaymentPolicyHelpers.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STArray.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STObject.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/STVector256.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/digest.h>

#include <algorithm>
#include <cstdint>
#include <expected>
#include <limits>
#include <set>
#include <unordered_set>
#include <utility>
#include <vector>

namespace xrpl {
namespace credentials {

bool
checkExpired(SLE const& sleCredential, NetClock::time_point const& closed)
{
    std::uint32_t const exp =
        sleCredential[~sfExpiration].value_or(std::numeric_limits<std::uint32_t>::max());
    std::uint32_t const now = closed.time_since_epoch().count();
    return now > exp;
}

[[nodiscard]]
static std::expected<bool, TER>
removeExpired(ApplyView& view, STVector256 const& arr, beast::Journal const j)
{
    auto const closeTime = view.header().parentCloseTime;
    bool foundExpired = false;

    for (auto const& h : arr)
    {
        // Credentials already checked in preclaim. Look only for expired here.
        if (view.rules().enabled(fixCleanup3_4_0) && h.isZero())
            return std::unexpected(tecINTERNAL);  // LCOV_EXCL_LINE

        auto const k = keylet::credential(h);
        auto const sleCred = view.peek(k);

        if (sleCred && checkExpired(*sleCred, closeTime))
        {
            JLOG(j.trace()) << "Credentials are expired. Cred: " << sleCred->getText();
            // delete expired credentials even if the transaction failed
            auto const err = deleteSLE(view, sleCred, j);
            if (view.rules().enabled(fixCleanup3_1_3) && !isTesSuccess(err))
                return std::unexpected(err);
            foundExpired = true;
        }
    }

    return foundExpired;
}

TER
deleteSLE(ApplyView& view, SLE::Ref sleCredential, beast::Journal j)
{
    if (!sleCredential)
        return tecNO_ENTRY;

    auto const delSLE = [&view, &sleCredential, j](
                            AccountID const& account, SField const& node, bool isOwner) -> TER {
        auto const sleAccount = view.peek(keylet::account(account));
        if (!sleAccount)
        {
            // LCOV_EXCL_START
            JLOG(j.fatal()) << "Internal error: can't retrieve Owner account.";
            return tecINTERNAL;
            // LCOV_EXCL_STOP
        }

        // Remove object from owner directory
        std::uint64_t const page = sleCredential->getFieldU64(node);
        if (!view.dirRemove(keylet::ownerDir(account), page, sleCredential->key(), false))
        {
            // LCOV_EXCL_START
            JLOG(j.fatal()) << "Unable to delete Credential from owner.";
            return tefBAD_LEDGER;
            // LCOV_EXCL_STOP
        }

        if (isOwner)
            decreaseOwnerCountForObject(view, sleAccount, sleCredential, 1, j);

        return tesSUCCESS;
    };

    auto const issuer = sleCredential->getAccountID(sfIssuer);
    auto const subject = sleCredential->getAccountID(sfSubject);
    bool const accepted = sleCredential->isFlag(lsfAccepted);

    auto err = delSLE(issuer, sfIssuerNode, !accepted || (subject == issuer));
    if (!isTesSuccess(err))
        return err;

    if (subject != issuer)
    {
        err = delSLE(subject, sfSubjectNode, accepted);
        if (!isTesSuccess(err))
            return err;
    }

    // Remove object from ledger
    view.erase(sleCredential);

    return tesSUCCESS;
}

NotTEC
checkFields(STTx const& tx, Rules const& rules, beast::Journal j)
{
    if (!tx.isFieldPresent(sfCredentialIDs))
        return tesSUCCESS;

    auto const& credentials = tx.getFieldV256(sfCredentialIDs);
    if (credentials.empty() || (credentials.size() > kMaxCredentialsArraySize))
    {
        JLOG(j.trace()) << "Malformed transaction: Credentials array size is invalid: "
                        << credentials.size();
        return temMALFORMED;
    }

    if (rules.enabled(fixCleanup3_4_0) &&
        std::ranges::any_of(credentials, [](UInt256 const& id) { return id.isZero(); }))
    {
        JLOG(j.trace()) << "Malformed transaction: zero credential ID.";
        return temMALFORMED;
    }

    std::unordered_set<UInt256> duplicates;
    for (auto const& cred : credentials)
    {
        auto [it, ins] = duplicates.insert(cred);
        if (!ins)
        {
            JLOG(j.trace()) << "Malformed transaction: duplicates in credentials.";
            return temMALFORMED;
        }
    }

    return tesSUCCESS;
}

TER
valid(STTx const& tx, ReadView const& view, AccountID const& src, beast::Journal j)
{
    if (!tx.isFieldPresent(sfCredentialIDs))
        return tesSUCCESS;

    auto const& credIDs(tx.getFieldV256(sfCredentialIDs));
    for (auto const& h : credIDs)
    {
        if (view.rules().enabled(fixCleanup3_4_0) && h.isZero())
        {
            // LCOV_EXCL_START
            JLOG(j.trace()) << "Zero credential ID.";
            return tecINTERNAL;
            // LCOV_EXCL_STOP
        }

        auto const sleCred = view.read(keylet::credential(h));
        if (!sleCred)
        {
            JLOG(j.trace()) << "Credential doesn't exist. Cred: " << h;
            return tecBAD_CREDENTIALS;
        }

        if (sleCred->getAccountID(sfSubject) != src)
        {
            JLOG(j.trace()) << "Credential doesn't belong to the source account. Cred: " << h;
            return tecBAD_CREDENTIALS;
        }

        if (!sleCred->isFlag(lsfAccepted))
        {
            JLOG(j.trace()) << "Credential isn't accepted. Cred: " << h;
            return tecBAD_CREDENTIALS;
        }

        // Expiration checks are in doApply
    }

    return tesSUCCESS;
}

TER
validDomain(ReadView const& view, UInt256 domainID, AccountID const& subject)
{
    // Note, permissioned domain objects can be deleted at any time
    auto const slePD = view.read(keylet::permissionedDomain(domainID));
    if (!slePD)
        return tecOBJECT_NOT_FOUND;

    auto const closeTime = view.header().parentCloseTime;
    bool foundExpired = false;
    for (auto const& h : slePD->getFieldArray(sfAcceptedCredentials))
    {
        auto const issuer = h.getAccountID(sfIssuer);
        auto const type = h.getFieldVL(sfCredentialType);
        auto const keyletCredential = keylet::credential(subject, issuer, makeSlice(type));
        auto const sleCredential = view.read(keyletCredential);

        // We cannot delete expired credentials, that would require ApplyView&
        // However we can check if credentials are expired. Expected transaction
        // flow is to use `validDomain` in preclaim, converting tecEXPIRED to
        // tesSUCCESS, then proceed to call `verifyValidDomain` in doApply. This
        // allows expired credentials to be deleted by any transaction.
        if (sleCredential)
        {
            if (checkExpired(*sleCredential, closeTime))
            {
                foundExpired = true;
                continue;
            }
            if (sleCredential->isFlag(lsfAccepted))
            {
                return tesSUCCESS;
            }

            continue;
        }
    }

    return foundExpired ? tecEXPIRED : tecNO_AUTH;
}

TER
authorizedDepositPreauth(ReadView const& view, STVector256 const& credIDs, AccountID const& dst)
{
    std::set<std::pair<AccountID, Slice>> sorted;
    std::vector<SLE::const_pointer> lifeExtender;
    lifeExtender.reserve(credIDs.size());
    for (auto const& h : credIDs)
    {
        if (view.rules().enabled(fixCleanup3_4_0) && h.isZero())
            return tefINTERNAL;  // LCOV_EXCL_LINE

        auto sleCred = view.read(keylet::credential(h));
        if (!sleCred)            // already checked in preclaim
            return tefINTERNAL;  // LCOV_EXCL_LINE

        auto [it, ins] = sorted.emplace((*sleCred)[sfIssuer], (*sleCred)[sfCredentialType]);
        if (!ins)
            return tefINTERNAL;  // LCOV_EXCL_LINE
        lifeExtender.push_back(std::move(sleCred));
    }

    if (!DepositPreauthEntryR(dst, sorted, view))
        return tecNO_PERMISSION;

    return tesSUCCESS;
}

std::set<std::pair<AccountID, Slice>>
makeSorted(STArray const& credentials)
{
    std::set<std::pair<AccountID, Slice>> out;
    for (auto const& cred : credentials)
    {
        auto [it, ins] = out.emplace(cred[sfIssuer], cred[sfCredentialType]);
        if (!ins)
            return {};
    }
    return out;
}

NotTEC
checkArray(STArray const& credentials, unsigned maxSize, beast::Journal j)
{
    if (credentials.empty() || (credentials.size() > maxSize))
    {
        JLOG(j.trace()) << "Malformed transaction: "
                           "Invalid credentials size: "
                        << credentials.size();
        return credentials.empty() ? temARRAY_EMPTY : temARRAY_TOO_LARGE;
    }

    std::unordered_set<UInt256> duplicates;
    for (auto const& credential : credentials)
    {
        auto const& issuer = credential[sfIssuer];
        if (!issuer)
        {
            JLOG(j.trace()) << "Malformed transaction: "
                               "Issuer account is invalid: "
                            << to_string(issuer);
            return temINVALID_ACCOUNT_ID;
        }

        auto const ct = credential[sfCredentialType];
        if (ct.empty() || (ct.size() > kMaxCredentialTypeLength))
        {
            JLOG(j.trace()) << "Malformed transaction: "
                               "Invalid credentialType size: "
                            << ct.size();
            return temMALFORMED;
        }

        auto [it, ins] = duplicates.insert(sha512Half(issuer, ct));
        if (!ins)
        {
            JLOG(j.trace()) << "Malformed transaction: "
                               "duplicates in credentials.";
            return temMALFORMED;
        }
    }

    return tesSUCCESS;
}

}  // namespace credentials

TER
verifyValidDomain(ApplyView& view, AccountID const& account, UInt256 domainID, beast::Journal j)
{
    auto const slePD = view.read(keylet::permissionedDomain(domainID));
    if (!slePD)
        return tecOBJECT_NOT_FOUND;

    // Collect all matching credentials on a side, so we can remove expired ones
    // We may finish the loop with this collection empty, it's fine.
    STVector256 credentials;
    for (auto const& h : slePD->getFieldArray(sfAcceptedCredentials))
    {
        auto const issuer = h.getAccountID(sfIssuer);
        auto const type = h.getFieldVL(sfCredentialType);
        auto const keyletCredential = keylet::credential(account, issuer, makeSlice(type));
        if (view.exists(keyletCredential))
            credentials.pushBack(keyletCredential.key);
    }

    auto const foundExpired = credentials::removeExpired(view, credentials, j);
    if (!foundExpired.has_value())
        return foundExpired.error();

    for (auto const& h : credentials)
    {
        auto const sleCredential = view.read(keylet::credential(h));
        if (!sleCredential)
            continue;  // expired, i.e. deleted in credentials::removeExpired

        if (sleCredential->isFlag(lsfAccepted))
            return tesSUCCESS;
    }

    return *foundExpired ? tecEXPIRED : tecNO_PERMISSION;
}

static bool
depositNoauthLive(ReadView const& view, Keylet const& noauthKey)
{
    auto const sleNoauth = view.read(noauthKey);
    if (!sleNoauth)
        return false;
    return !credentials::checkExpired(*sleNoauth, view.header().parentCloseTime);
}

TER
checkDepositPreauth(
    STTx const& tx,
    ReadView const& view,
    AccountID const& src,
    AccountID const& dst,
    SLE::ConstRef sleDst,
    beast::Journal j,
    bool skipAllowForUnwedge)
{
    if (!sleDst || src == dst)
        return tesSUCCESS;

    bool const paymentPolicy = view.rules().enabled(featurePaymentPolicy);

    if (paymentPolicy && ((sleDst->getFlags() & lsfDepositNoauth) != 0u))
    {
        if (depositNoauthLive(view, keylet::depositNoauth(dst, src)))
            return tecDEPOSIT_NOAUTH;

        if (auto const sleSetNoauth = view.read(keylet::depositSetNoauth(dst)))
        {
            for (auto const& entry : sleSetNoauth->getFieldArray(sfProviders))
            {
                AccountID const provider = entry.getAccountID(sfAccount);
                if (depositNoauthLive(view, keylet::depositNoauth(provider, src)))
                    return tecDEPOSIT_NOAUTH;
            }
        }
    }

    // Obligation create (Check/PayChan/Escrow) and dest-signed cash unwedge:
    // classic DepositAuth must not block; DepositNoauth still does.
    if (skipAllowForUnwedge)
        return tesSUCCESS;

    if ((sleDst->getFlags() & lsfDepositAuth) != 0u)
    {
        if (DepositPreauthEntryR(dst, src, view))
            return tesSUCCESS;

        if (paymentPolicy)
        {
            if (auto const sleSetPreauth = view.read(keylet::depositSetPreauth(dst)))
            {
                for (auto const& entry : sleSetPreauth->getFieldArray(sfProviders))
                {
                    AccountID const provider = entry.getAccountID(sfAccount);
                    if (DepositPreauthEntryR(provider, src, view))
                        return tesSUCCESS;
                }
            }
        }

        return !tx.isFieldPresent(sfCredentialIDs)
            ? tecNO_PERMISSION
            : credentials::authorizedDepositPreauth(view, tx.getFieldV256(sfCredentialIDs), dst);
    }

    return tesSUCCESS;
}

TER
cleanupExpiredCredentials(STTx const& tx, ApplyView& view, beast::Journal j)
{
    if (tx.isFieldPresent(sfCredentialIDs))
    {
        auto const foundExpired =
            credentials::removeExpired(view, tx.getFieldV256(sfCredentialIDs), j);
        if (!foundExpired.has_value())
            return foundExpired.error();
        if (*foundExpired)
            return tecEXPIRED;
    }

    return tesSUCCESS;
}

static TER
eraseExpiredNoauth(ApplyView& view, SLE::Ref sleNoauth, Keylet const& noauthKey, beast::Journal j)
{
    AccountID const account = sleNoauth->getAccountID(sfAccount);
    std::uint64_t const page = sleNoauth->getFieldU64(sfOwnerNode);
    if (!view.dirRemove(keylet::ownerDir(account), page, noauthKey.key, false))
    {
        JLOG(j.error()) << "expire noauth: failed dirRemove " << to_string(noauthKey.key);
        return tefBAD_LEDGER;
    }
    auto const sleOwner = view.peek(keylet::account(account));
    if (!sleOwner)
        return tesSUCCESS;
    decreaseOwnerCountForObject(view, sleOwner, sleNoauth, 1, j);
    view.erase(sleNoauth);
    return tesSUCCESS;
}

static TER
expireDepositNoauthIfNeeded(ApplyView& view, Keylet const& noauthKey, beast::Journal j)
{
    auto const sleNoauth = view.peek(noauthKey);
    if (!sleNoauth)
        return tesSUCCESS;

    if (!credentials::checkExpired(*sleNoauth, view.header().parentCloseTime))
        return tecDEPOSIT_NOAUTH;

    return eraseExpiredNoauth(view, sleNoauth, noauthKey, j);
}

static TER
expireWithdrawNoauthIfNeeded(ApplyView& view, Keylet const& noauthKey, beast::Journal j)
{
    auto const sleNoauth = view.peek(noauthKey);
    if (!sleNoauth)
        return tesSUCCESS;

    if (!credentials::checkExpired(*sleNoauth, view.header().parentCloseTime))
        return tecWITHDRAW_NOAUTH;

    return eraseExpiredNoauth(view, sleNoauth, noauthKey, j);
}

TER
verifyDepositPreauth(
    STTx const& tx,
    ApplyView& view,
    AccountID const& src,
    AccountID const& dst,
    SLE::ConstRef sleDst,
    beast::Journal j,
    bool skipAllowForUnwedge)
{
    if (auto const err = cleanupExpiredCredentials(tx, view, j); !isTesSuccess(err))
        return err;

    if (!sleDst || src == dst)
        return tesSUCCESS;

    bool const paymentPolicy = view.rules().enabled(featurePaymentPolicy);

    if (paymentPolicy && ((sleDst->getFlags() & lsfDepositNoauth) != 0u))
    {
        if (auto const ter = expireDepositNoauthIfNeeded(view, keylet::depositNoauth(dst, src), j);
            !isTesSuccess(ter))
            return ter;

        if (auto const sleSetNoauth = view.peek(keylet::depositSetNoauth(dst)))
        {
            for (auto const& entry : sleSetNoauth->getFieldArray(sfProviders))
            {
                AccountID const provider = entry.getAccountID(sfAccount);
                if (auto const ter =
                        expireDepositNoauthIfNeeded(view, keylet::depositNoauth(provider, src), j);
                    !isTesSuccess(ter))
                    return ter;
            }
        }
    }

    if (skipAllowForUnwedge)
        return tesSUCCESS;

    return checkDepositPreauth(tx, view, src, dst, sleDst, j, false);
}

static bool
withdrawNoauthLive(ReadView const& view, Keylet const& noauthKey)
{
    auto const sleNoauth = view.read(noauthKey);
    if (!sleNoauth)
        return false;
    return !credentials::checkExpired(*sleNoauth, view.header().parentCloseTime);
}

TER
checkWithdrawAuth(
    ReadView const& view,
    STTx const& tx,
    AccountID const& src,
    AccountID const& dst,
    SLE::ConstRef sleSrc,
    beast::Journal j,
    std::uint32_t destinationTag)
{
    if (!sleSrc || src == dst)
        return tesSUCCESS;

    bool const paymentPolicy = view.rules().enabled(featurePaymentPolicy);
    bool const hardFw = view.rules().enabled(featureFirewall) && view.exists(keylet::firewall(src));
    if (!paymentPolicy && !hardFw)
        return tesSUCCESS;

    bool const denyMode = hardFw || ((sleSrc->getFlags() & lsfWithdrawNoauth) != 0u);
    bool const allowMode = hardFw || ((sleSrc->getFlags() & lsfWithdrawAuth) != 0u);

    if (denyMode)
    {
        // Firewall deny uses tecFIREWALL_BLOCK; soft WithdrawNoauth stays as-is.
        auto const denyTer = hardFw ? TER{tecFIREWALL_BLOCK} : TER{tecWITHDRAW_NOAUTH};
        if (withdrawNoauthLive(view, keylet::withdrawNoauth(src, dst)))
            return denyTer;
        if (auto const sleSet = view.read(keylet::withdrawSetNoauth(src)))
        {
            for (auto const& entry : sleSet->getFieldArray(sfProviders))
            {
                AccountID const provider = entry.getAccountID(sfAccount);
                if (withdrawNoauthLive(view, keylet::withdrawNoauth(provider, dst)))
                    return denyTer;
            }
        }
    }

    if (allowMode)
    {
        if (view.exists(keylet::withdrawPreauth(src, dst, destinationTag)))
            return tesSUCCESS;
        if (auto const sleSet = view.read(keylet::withdrawSetPreauth(src)))
        {
            for (auto const& entry : sleSet->getFieldArray(sfProviders))
            {
                AccountID const provider = entry.getAccountID(sfAccount);
                if (view.exists(keylet::withdrawPreauth(provider, dst, destinationTag)))
                    return tesSUCCESS;
            }
        }
        if (!hardFw)
            return tecNO_PERMISSION;
        // Missing allow under Firewall: require cosign for src's own Firewall.
        auto const sleFw = view.read(keylet::firewall(src));
        if (!sleFw)
            return tecREQUIRES_COUNTERPARTY;
        if (isTesSuccess(
                verifyCounterpartyCosign(view, tx, sleFw->getAccountID(sfCounterparty), j)))
            return tesSUCCESS;
        return tecREQUIRES_COUNTERPARTY;
    }

    return tesSUCCESS;
}

TER
verifyWithdrawAuth(
    ApplyView& view,
    STTx const& tx,
    AccountID const& src,
    AccountID const& dst,
    SLE::ConstRef sleSrc,
    beast::Journal j,
    std::uint32_t destinationTag)
{
    if (!sleSrc || src == dst)
        return tesSUCCESS;

    if (!view.rules().enabled(featurePaymentPolicy))
        return tesSUCCESS;

    if ((sleSrc->getFlags() & lsfWithdrawNoauth) != 0u)
    {
        if (auto const ter =
                expireWithdrawNoauthIfNeeded(view, keylet::withdrawNoauth(src, dst), j);
            !isTesSuccess(ter))
            return ter;
        if (auto const sleSet = view.read(keylet::withdrawSetNoauth(src)))
        {
            for (auto const& entry : sleSet->getFieldArray(sfProviders))
            {
                AccountID const provider = entry.getAccountID(sfAccount);
                if (auto const ter = expireWithdrawNoauthIfNeeded(
                        view, keylet::withdrawNoauth(provider, dst), j);
                    !isTesSuccess(ter))
                    return ter;
            }
        }
    }

    return checkWithdrawAuth(view, tx, src, dst, sleSrc, j, destinationTag);
}

TER
verifyUncontrolledValueExit(
    ReadView const& view,
    AccountID const& account,
    SLE::ConstRef sleSrc,
    beast::Journal j)
{
    if (!sleSrc)
        return tesSUCCESS;

    bool const paymentPolicy = view.rules().enabled(featurePaymentPolicy);
    bool const hardFw =
        view.rules().enabled(featureFirewall) && view.exists(keylet::firewall(account));
    if (!paymentPolicy && !hardFw)
        return tesSUCCESS;

    // Hard Firewall: checkFirewall already requires CP for block-class.
    if (hardFw)
        return tesSUCCESS;

    auto const flags = sleSrc->getFlags();
    if ((flags & lsfWithdrawAuth) != 0u || (flags & lsfWithdrawNoauth) != 0u)
    {
        JLOG(j.trace()) << "Withdraw policy: uncontrolled value exit blocked for "
                        << to_string(account);
        return tecNO_PERMISSION;
    }

    return tesSUCCESS;
}

bool
accountBlocksUncontrolledExit(ReadView const& view, AccountID const& account)
{
    if (view.rules().enabled(featureFirewall) && view.exists(keylet::firewall(account)))
        return true;

    if (!view.rules().enabled(featurePaymentPolicy))
        return false;

    auto const sle = view.read(keylet::account(account));
    if (!sle)
        return false;

    auto const flags = sle->getFlags();
    return (flags & lsfWithdrawAuth) != 0u || (flags & lsfWithdrawNoauth) != 0u;
}

}  // namespace xrpl
