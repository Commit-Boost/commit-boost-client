use std::fmt::{Display, Formatter};

use blst::BLST_ERROR;
use thiserror::Error;
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlstErrorWrapper {
    BlstSuccess(BLST_ERROR),
    BlstBadEncoding(BLST_ERROR),
    BlstPointNotOnCurve(BLST_ERROR),
    BlstPointNotInGroup(BLST_ERROR),
    BlstAggrTypeMismatch(BLST_ERROR),
    BlstVerifyFail(BLST_ERROR),
    BlstPkIsInfinity(BLST_ERROR),
    BlstBadScalar(BLST_ERROR),
}

impl Display for BlstErrorWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BlstErrorWrapper::BlstSuccess(_) => write!(f, "BLST_SUCCESS"),
            BlstErrorWrapper::BlstBadEncoding(_) => write!(f, "BLST_BAD_ENCODING"),
            BlstErrorWrapper::BlstPointNotOnCurve(_) => write!(f, "BLST_POINT_NOT_ON_CURVE"),
            BlstErrorWrapper::BlstPointNotInGroup(_) => write!(f, "BLST_POINT_NOT_IN_GROUP"),
            BlstErrorWrapper::BlstAggrTypeMismatch(_) => write!(f, "BLST_AGGR_TYPE_MISMATCH"),
            BlstErrorWrapper::BlstVerifyFail(_) => write!(f, "BLST_VERIFY_FAIL"),
            BlstErrorWrapper::BlstPkIsInfinity(_) => write!(f, "BLST_PK_IS_INFINITY"),
            BlstErrorWrapper::BlstBadScalar(_) => write!(f, "BLST_BAD_SCALAR"),
        }
    }
}
impl From<BLST_ERROR> for BlstErrorWrapper {
    fn from(value: BLST_ERROR) -> Self {
        match value {
            BLST_ERROR::BLST_SUCCESS => BlstErrorWrapper::BlstSuccess(BLST_ERROR::BLST_SUCCESS),
            BLST_ERROR::BLST_BAD_ENCODING => {
                BlstErrorWrapper::BlstBadEncoding(BLST_ERROR::BLST_BAD_ENCODING)
            }
            BLST_ERROR::BLST_POINT_NOT_ON_CURVE => {
                BlstErrorWrapper::BlstPointNotOnCurve(BLST_ERROR::BLST_POINT_NOT_ON_CURVE)
            }
            BLST_ERROR::BLST_POINT_NOT_IN_GROUP => {
                BlstErrorWrapper::BlstPointNotInGroup(BLST_ERROR::BLST_POINT_NOT_IN_GROUP)
            }
            BLST_ERROR::BLST_AGGR_TYPE_MISMATCH => {
                BlstErrorWrapper::BlstAggrTypeMismatch(BLST_ERROR::BLST_AGGR_TYPE_MISMATCH)
            }
            BLST_ERROR::BLST_VERIFY_FAIL => {
                BlstErrorWrapper::BlstVerifyFail(BLST_ERROR::BLST_VERIFY_FAIL)
            }
            BLST_ERROR::BLST_PK_IS_INFINITY => {
                BlstErrorWrapper::BlstPkIsInfinity(BLST_ERROR::BLST_PK_IS_INFINITY)
            }
            BLST_ERROR::BLST_BAD_SCALAR => {
                BlstErrorWrapper::BlstBadScalar(BLST_ERROR::BLST_BAD_SCALAR)
            }
        }
    }
}
