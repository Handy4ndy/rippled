#pragma once

#include <xrpl/tx/transactors/payment/WithdrawAuthorization.h>

namespace xrpl {

class WithdrawPreauth : public WithdrawAuthorization
{
public:
    using WithdrawAuthorization::WithdrawAuthorization;
};

}  // namespace xrpl
