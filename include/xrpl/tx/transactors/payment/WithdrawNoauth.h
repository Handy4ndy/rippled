#pragma once

/// Thin wrapper — all logic lives in WithdrawAuthorization.
/// This class exists so that ttWITHDRAW_NOAUTH retains the name
/// "WithdrawNoauth" in the JSON wire format and jss namespace.
#include <xrpl/tx/transactors/payment/WithdrawAuthorization.h>

namespace xrpl {

class WithdrawNoauth : public WithdrawAuthorization
{
public:
    using WithdrawAuthorization::WithdrawAuthorization;
};

}  // namespace xrpl
