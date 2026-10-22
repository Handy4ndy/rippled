#include <test/jtx/sig.h>

#include <test/jtx/Env.h>
#include <test/jtx/JTx.h>
#include <test/jtx/utility.h>

#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/Sign.h>
#include <xrpl/protocol/jss.h>

namespace xrpl::test::jtx {

void
Sig::operator()(Env&, JTx& jt) const
{
    if (!manual_)
        return;
    if (subField_ == nullptr)
        jt.fillSig = false;
    if (account_)
    {
        // VFALCO Inefficient pre-C++14
        auto const account = *account_;
        auto const callback = [subField = subField_, account](Env& env, JTx& jtx) {
            // Where to put the signature. Supports sfCounterPartySignature and sfSponsorSignature.
            auto& sigObject = subField ? jtx[*subField] : jtx.jv;

            jtx::sign(
                jtx.jv,
                account,
                sigObject,
                signingPrefix(jtx::signatureRole(subField), false, env.current()->rules()));
        };
        if (subField_ == nullptr)
        {
            jt.mainSigners.emplace_back(callback);
        }
        else
        {
            jt.postSigners.emplace_back(callback);
        }
    }
}

void
CpSigs::operator()(Env&, JTx& jt) const
{
    json::Value arr{json::ValueType::Array};
    for (std::size_t i = 0; i < accounts_.size(); ++i)
    {
        json::Value wrap;
        wrap[sfCounterpartySig.getJsonName()] = json::Value{json::ValueType::Object};
        arr.append(std::move(wrap));
    }
    jt[sfCounterpartySignatures.getJsonName()] = std::move(arr);

    for (std::size_t i = 0; i < accounts_.size(); ++i)
    {
        auto const account = accounts_[i];
        auto const index = static_cast<json::UInt>(i);
        jt.postSigners.emplace_back([account, index](Env& env, JTx& jtx) {
            auto& sigObject =
                jtx[sfCounterpartySignatures.getJsonName()][index][sfCounterpartySig.getJsonName()];
            jtx::sign(
                jtx.jv,
                account,
                sigObject,
                signingPrefix(SignatureRole::Counterparty, false, env.current()->rules()));
        });
    }
}

}  // namespace xrpl::test::jtx
