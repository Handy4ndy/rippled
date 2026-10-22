#pragma once

/// Thin wrapper — all logic lives in WithdrawAuthorization.
/// This class exists so that ttWITHDRAW_PREAUTH retains the name
/// "WithdrawPreauth" in the JSON wire format and jss namespace.
#include <xrpl/tx/transactors/payment/WithdrawAuthorization.h>

namespace xrpl {

class WithdrawPreauth : public WithdrawAuthorization
{
public:
    using WithdrawAuthorization::WithdrawAuthorization;
};

}  // namespace xrpl
