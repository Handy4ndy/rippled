#pragma once

#include <test/jtx/Account.h>
#include <test/jtx/Env.h>
#include <test/jtx/JTx.h>
#include <test/jtx/tags.h>

#include <xrpl/protocol/SField.h>

#include <initializer_list>
#include <optional>
#include <vector>

namespace xrpl::test::jtx {

/**
 * Set the regular signature on a JTx.
 * @note For multisign, use msig.
 */
class Sig
{
private:
    bool manual_ = true;
    /**
     * Alternative transaction object field in which to place the signature.
     *
     * subField is only supported if an account_ is provided as well.
     */
    SField const* const subField_ = nullptr;
    /**
     * Account that will generate the signature.
     *
     * If not provided, no signature will be added by this helper. See also
     * Env::autofillSig.
     */
    std::optional<Account> account_;
    /**
     * Used solely as a convenience placeholder for ctors that do _not_ specify
     * a subfield.
     */
    static constexpr SField const* kTopLevel = nullptr;

public:
    explicit Sig(AutofillT) : manual_(false)
    {
    }

    explicit Sig(NoneT)
    {
    }

    explicit Sig(SField const* subField, Account const& account)
        : subField_(subField), account_(account)
    {
    }

    explicit Sig(SField const& subField, Account const& account) : Sig(&subField, account)
    {
    }

    explicit Sig(Account const& account) : Sig(kTopLevel, account)
    {
    }

    void
    operator()(Env&, JTx& jt) const;
};

/**
 * Attach sfCounterpartySignatures (array of CounterpartySig) and sign each
 * entry with the given accounts. Mutually exclusive with a single
 * sfCounterpartySignature on the same JTx.
 */
class CpSigs
{
private:
    std::vector<Account> accounts_;

public:
    explicit CpSigs(std::initializer_list<Account> accounts) : accounts_(accounts)
    {
    }

    explicit CpSigs(std::vector<Account> accounts) : accounts_(std::move(accounts))
    {
    }

    void
    operator()(Env&, JTx& jt) const;
};

}  // namespace xrpl::test::jtx
