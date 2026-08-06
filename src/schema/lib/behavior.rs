// Handwritten operational behavior for the authority-verified ordinary Persona Interface.
//
// The strict bootstrap projection owns every structural type below. This file
// owns only behavior the current bootstrap language cannot yet express:
// structural runtime traits, the ordinary Input/Output role seating, and the
// allocated Signal frame boundary.

use rkyv::{
    Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize,
    rancor::Source as _,
};
pub use signal_standard::schema::lib::{
    ArchivedWireValue, WireShape, WireShapeError, WireValue,
};
fn one_field(mut fields: Vec<WireValue>) -> Result<WireValue, WireShapeError> {
    if fields.len() != 1 { return Err(WireShapeError); }
    Ok(fields.pop().expect("one field checked"))
}

macro_rules! wire_traits {
    ($name:ident) => {
        impl Clone for $name { fn clone(&self) -> Self { Self::from_wire(self.to_wire()).expect("a projected value revalidates") } }
        impl std::fmt::Debug for $name { fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { self.to_wire().fmt(formatter) } }
        impl PartialEq for $name { fn eq(&self, other: &Self) -> bool { self.to_wire() == other.to_wire() } }
        impl Eq for $name {}
    };
}
macro_rules! wire_external_newtype {
    ($name:ident, $inner:ty) => {
        impl WireShape for $name {
            fn to_wire(&self) -> WireValue { self.payload().to_wire() }
            fn from_wire(value: WireValue) -> Result<Self, WireShapeError> { Ok(Self::new(<$inner as WireShape>::from_wire(value)?)) }
        }
        wire_traits!($name);
        #[cfg(feature = "dotos-text")]
        impl dotos::DotosEncode for $name {
            fn to_dotos(&self) -> std::string::String {
                dotos::DotosEncode::to_dotos(self.payload())
            }
        }
        #[cfg(feature = "dotos-text")]
        impl dotos::DotosDecode for $name {
            fn from_dotos_block(block: &dotos::Block) -> Result<Self, dotos::DotosDecodeError> {
                <$inner as dotos::DotosDecode>::from_dotos_block(block).map(Self::new)
            }
        }
    };
}
macro_rules! wire_newtype {
    ($name:ident, $inner:ty) => {
        impl $name {
            pub fn new(payload: $inner) -> Self { Self(payload) }
            pub fn payload(&self) -> &$inner { &self.0 }
            pub fn into_payload(self) -> $inner { self.0 }
        }
        impl WireShape for $name {
            fn to_wire(&self) -> WireValue { self.0.to_wire() }
            fn from_wire(value: WireValue) -> Result<Self, WireShapeError> { Ok(Self(<$inner as WireShape>::from_wire(value)?)) }
        }
        wire_traits!($name);
        #[cfg(feature = "dotos-text")]
        impl dotos::DotosEncode for $name {
            fn to_dotos(&self) -> std::string::String {
                dotos::DotosEncode::to_dotos(&self.0)
            }
        }
        #[cfg(feature = "dotos-text")]
        impl dotos::DotosDecode for $name {
            fn from_dotos_block(block: &dotos::Block) -> Result<Self, dotos::DotosDecodeError> {
                <$inner as dotos::DotosDecode>::from_dotos_block(block).map(Self)
            }
        }
    };
}
macro_rules! wire_struct {
    ($name:ident { $($field:ident: $field_type:ty),* $(,)? }) => {
        impl WireShape for $name {
            fn to_wire(&self) -> WireValue { WireValue::Product(vec![$(self.$field.to_wire()),*]) }
            fn from_wire(value: WireValue) -> Result<Self, WireShapeError> {
                let WireValue::Product(fields) = value else { return Err(WireShapeError) };
                let mut fields = fields.into_iter();
                let result = Self { $($field: <$field_type as WireShape>::from_wire(fields.next().ok_or(WireShapeError)?)?),* };
                if fields.next().is_some() { return Err(WireShapeError); }
                Ok(result)
            }
        }
        wire_traits!($name);
        #[cfg(feature = "dotos-text")]
        impl dotos::DotosEncode for $name {
            fn to_dotos(&self) -> std::string::String {
                dotos::Delimiter::Parenthesis.wrap([
                    $(dotos::DotosEncode::to_dotos(&self.$field)),*
                ])
            }
        }
        #[cfg(feature = "dotos-text")]
        impl dotos::DotosDecode for $name {
            fn from_dotos_block(block: &dotos::Block) -> Result<Self, dotos::DotosDecodeError> {
                let body = dotos::DotosBody::from_delimited(
                    block,
                    dotos::Delimiter::Parenthesis,
                    stringify!($name),
                )?;
                let expected = 0usize $(+ {
                    let _ = stringify!($field);
                    1usize
                })*;
                #[allow(unused_mut, unused_variables)]
                let mut fields = body.expect_fields(stringify!($name), expected)?.iter();
                Ok(Self {
                    $($field: <$field_type as dotos::DotosDecode>::from_dotos_block(
                        fields.next().expect("field count checked"),
                    )?),*
                })
            }
        }
    };
}
macro_rules! wire_enum {
    ($name:ident {
        unit { $($unit_ordinal:literal => $unit:ident : $unit_visible:literal),* $(,)? }
        unary { $($unary_ordinal:literal => $unary:ident($payload:ty) : $unary_visible:literal),* $(,)? }
    }) => {
        impl WireShape for $name {
            fn to_wire(&self) -> WireValue {
                match self {
                    $(Self::$unit => WireValue::Variant { ordinal: $unit_ordinal, fields: Vec::new() },)*
                    $(Self::$unary(payload) => WireValue::Variant { ordinal: $unary_ordinal, fields: vec![payload.to_wire()] },)*
                }
            }
            fn from_wire(value: WireValue) -> Result<Self, WireShapeError> {
                let WireValue::Variant { ordinal, fields } = value else { return Err(WireShapeError) };
                match ordinal {
                    $($unit_ordinal if fields.is_empty() => Ok(Self::$unit),)*
                    $($unary_ordinal => Ok(Self::$unary(<$payload as WireShape>::from_wire(one_field(fields)?)?)),)*
                    _ => Err(WireShapeError),
                }
            }
        }
        wire_traits!($name);
        #[cfg(feature = "dotos-text")]
        impl dotos::DotosEncode for $name {
            fn to_dotos(&self) -> std::string::String {
                match self {
                    $(Self::$unit => $unit_visible.to_owned(),)*
                    $(Self::$unary(payload) => format!(
                        "{}.{}",
                        $unary_visible,
                        dotos::DotosEncode::to_dotos(payload),
                    ),)*
                }
            }
        }
        #[cfg(feature = "dotos-text")]
        impl dotos::DotosDecode for $name {
            fn from_dotos_block(block: &dotos::Block) -> Result<Self, dotos::DotosDecodeError> {
                if let Some(variant) = block.demote_to_string() {
                    return match variant {
                        $($unit_visible => Ok(Self::$unit),)*
                        _ => Err(dotos::DotosDecodeError::UnknownVariant {
                            enum_name: stringify!($name),
                            variant: variant.to_owned(),
                        }),
                    };
                }
                let (head, payload) = block.as_application().ok_or(
                    dotos::DotosDecodeError::ExpectedAtom { type_name: stringify!($name) },
                )?;
                let _ = &payload;
                let variant = head.demote_to_string().ok_or(
                    dotos::DotosDecodeError::ExpectedAtom { type_name: stringify!($name) },
                )?;
                match variant {
                    $($unary_visible => Ok(Self::$unary(
                        <$payload as dotos::DotosDecode>::from_dotos_block(payload)?,
                    )),)*
                    _ => Err(dotos::DotosDecodeError::UnknownVariant {
                        enum_name: stringify!($name),
                        variant: variant.to_owned(),
                    }),
                }
            }
        }
    };
}
wire_external_newtype!(z2VdZ4, std::string::String);
wire_struct!(z2VUiL { field_0: z2VZMH, field_1: z2VL5X, field_2: z2VPdA });
wire_struct!(z2VNo7 { field_0: Option< z2Vb3i>, field_1: Option< z2VReV> });
wire_external_newtype!(z2VUfX, u64);
wire_enum!(z2VZZu { unit { 1 => z2VPcz : "Authorized", 2 => z2VdWC : "NonJudgement", 3 => z2VMGJ : "Deferred" } unary { 0 => z2VTm7(z2VXA2) : "Escalate", 4 => z2VUM8(z2VM1c) : "Rejected" } });
wire_external_newtype!(z2VMiY, std::string::String);
wire_struct!(z2VcHz { field_0: z2VfEn, field_1: z2VQHy, field_2: z2VMbZ });
wire_struct!(z2Vbch { field_0: z2VZMH, field_1: z2VL5X, field_2: z2VVvg });
wire_struct!(z2VP1D { field_0: z2VbTN, field_1: z2VUfX, field_2: Vec< z2VL5X> });
wire_struct!(z2VSJ5 { field_0: z2VWaA, field_1: z2VPfK });
wire_struct!(z2VTRq { field_0: z2Vf4i, field_1: z2VVvg });
wire_struct!(z2VVC4 { field_0: z2VL5X, field_1: z2VRpF });
wire_struct!(z2VQsx { field_0: z2VbxF, field_1: z2VbxF, field_2: z2VL5X });
wire_struct!(z2VYrq { field_0: z2VL5X, field_1: z2VVvg });
wire_struct!(z2VPDB { field_0: z2VduC, field_1: z2VLn9 });
wire_external_newtype!(z2VVmW, Vec< z2VLMo>);
wire_struct!(z2Vf4i { field_0: z2VP1D, field_1: Vec< z2VYrq> });
wire_struct!(z2VRPv { field_0: z2VaDY, field_1: z2Vevu, field_2: z2VZZu, field_3: z2Vf4i });
wire_enum!(z2VPMJ { unit { 0 => z2VRwy : "InvalidSignature", 1 => z2VWCR : "UnknownSigner", 2 => z2VWYS : "ReplayAttempted", 3 => z2VN1i : "Valid", 4 => z2Vdxz : "Revoked", 5 => z2VYVC : "Expired" } unary {  } });
wire_struct!(z2VVvg { field_0: z2VPCX, field_1: z2VdZ4, field_2: z2VZjL });
wire_enum!(z2VYM1 { unit { 0 => z2VUdX : "ReplaceSamePriorityOverlap", 1 => z2VWW6 : "RejectSamePriorityOverlap" } unary {  } });
wire_struct!(z2VVNR { field_0: z2VdZJ, field_1: z2VL5X });
wire_struct!(z2VR27 { field_0: z2Vevu, field_1: z2VbzK, field_2: z2VaDY });
wire_struct!(z2VVqk { field_0: z2VQAt });
wire_external_newtype!(z2VZjL, std::string::String);
wire_struct!(z2VWVn { field_0: z2VbEU, field_1: z2VZMH });
wire_struct!(z2VPN6 { field_0: z2VUph, field_1: Option< z2VeNt>, field_2: Option< z2VWkd> });
wire_struct!(z2VMG4 { field_0: z2VL5X, field_1: z2VRpF });
wire_struct!(z2VeMQ { field_0: z2VL5X, field_1: z2VW6A, field_2: z2VMEA });
wire_struct!(z2VYV1 { field_0: z2VSrE, field_1: Vec< z2VPfK> });
wire_struct!(z2VNJc { field_0: z2VL5X });
wire_struct!(z2VUwF { field_0: z2VUph, field_1: z2VbxF, field_2: Vec< z2VL5X>, field_3: z2Vbwi });
wire_enum!(z2Vb2e { unit {  } unary { 0 => z2VVVY(z2VSJ5) : "Signature", 1 => z2VMfb(z2VYV1) : "Founded", 2 => z2VY7q(z2Vd8U) : "Proposal" } });
wire_external_newtype!(z2VUph, std::string::String);
wire_external_newtype!(z2VbxF, std::string::String);
wire_struct!(z2VWHY { field_0: z2VUph, field_1: z2VZ96 });
wire_struct!(z2VZTd { field_0: z2VL5X, field_1: z2VdZ4 });
wire_newtype!(z2VdKy, z2VbxF);
wire_struct!(z2Vb3U { field_0: z2VeKX });
wire_enum!(z2VXA2 { unit { 1 => z2VXZu : "Psyche" } unary { 0 => z2VNgA(z2VL5X) : "SmarterAgent", 2 => z2Vd25(z2VdZJ) : "Workflow" } });
wire_external_newtype!(z2VWfb, std::string::String);
wire_struct!(z2VWk3 { field_0: z2VUph, field_1: z2VL5X, field_2: z2VcSh });
wire_newtype!(z2VSrv, z2VbxF);
wire_struct!(z2VPdA { field_0: z2VahY, field_1: z2VMEA, field_2: z2VMEA, field_3: z2VMiY });
wire_struct!(z2VQY3 { field_0: z2VL5X, field_1: z2VZMH, field_2: Option< z2VaoB>, field_3: z2VVvg });
wire_enum!(z2VMjw { unit { 0 => z2VYHd : "RootFounded", 1 => z2VVC3 : "ProposalPending", 2 => z2VSCj : "SignatureAccumulated", 3 => z2VQj9 : "Refused" } unary {  } });
wire_struct!(z2VQFm { field_0: z2VduC, field_1: z2VSrv, field_2: z2Vf4i, field_3: Vec< z2VTRq>, field_4: Vec< z2VM44>, field_5: Vec< z2VSX9>, field_6: Vec< z2Vcoi> });
wire_struct!(z2VL92 { field_0: z2VN9q });
wire_enum!(z2VM1c { unit { 1 => z2VNtq : "AgreementMissing", 3 => z2VYyM : "OutsideTimeWindow", 4 => z2VewY : "TimeNotProven" } unary { 0 => z2VQS6(z2VL5X) : "SignatureMissing", 2 => z2VaCD(z2VS8R) : "QuorumShort" } });
wire_enum!(z2VL5X { unit {  } unary { 0 => z2VQ5b(z2VMEA) : "Persona", 1 => z2VbvU(z2VMEA) : "Host", 2 => z2VM9k(z2VMEA) : "Developer", 3 => z2VQJp(z2VMEA) : "Agent", 4 => z2VLPe(z2VMEA) : "Cluster" } });
wire_enum!(z2VRbn { unit {  } unary { 0 => z2VR8C(z2VKuU) : "Threshold", 1 => z2VbgE(Vec< z2VTuy>) : "AllOf", 2 => z2VSh3(z2VXA2) : "Escalate", 3 => z2VWbV(Vec< z2VTuy>) : "AnyOf", 4 => z2Vc93(z2VWfb) : "WorkflowStep", 5 => z2VcqB(z2VL5X) : "Signature" } });
wire_external_newtype!(z2VSyf, std::string::String);
wire_struct!(z2Vd8U { field_0: z2VSrE, field_1: z2VL5X });
wire_external_newtype!(z2VN9q, std::string::String);
wire_external_newtype!(z2VUKd, u64);
wire_struct!(z2VbP2 { field_0: z2VUph, field_1: z2VL5X });
wire_enum!(z2VRpF { unit { 3 => z2VLdY : "AnyAuthorizedObject" } unary { 0 => z2VRtC(z2VLn9) : "ObjectKind", 1 => z2VVj1(z2VPDB) : "ComponentObject", 2 => z2VZus(z2VduC) : "Component" } });
wire_newtype!(z2VdZJ, z2VbxF);
wire_struct!(z2VQAt { field_0: z2VUph, field_1: z2VbxF, field_2: z2VdpP, field_3: Vec< z2VL5X>, field_4: Option< z2VdVm>, field_5: Option< z2VZ96>, field_6: Option< z2VeNt>, field_7: Option< z2VWkd>, field_8: Option< z2VeNt> });
wire_struct!(z2VPxW { field_0: z2VQ9E });
wire_enum!(z2VLn9 { unit { 0 => z2Vccv : "Head", 1 => z2VZ6i : "Time", 2 => z2VdH6 : "Contract", 3 => z2VQ1m : "Operation", 4 => z2VX3b : "Agreement" } unary {  } });
wire_enum!(z2VdpP { unit { 0 => z2VSNV : "Unavailable", 1 => z2VVCH : "Denied", 2 => z2VXkk : "Expired", 3 => z2VLSs : "Granted", 4 => z2VZVU : "Parked", 5 => z2VMX9 : "Pending", 6 => z2VcnK : "Signing" } unary {  } });
wire_struct!(z2VZcV { field_0: z2VUph, field_1: z2VL5X, field_2: z2VTRq });
wire_struct!(z2VQdW { field_0: z2VSL1, field_1: z2VUfX, field_2: Vec< z2VL5X> });
wire_struct!(z2VL1q { field_0: z2VN9q, field_1: z2VYwG, field_2: z2VL5X, field_3: z2VVvg, field_4: z2VVvg });
wire_enum!(z2VMvf { unit { 0 => z2VMRb : "Automatic", 1 => z2VWUM : "Manual" } unary {  } });
wire_struct!(z2VfB8 { field_0: z2VShF, field_1: z2Vb3i, field_2: z2VReV, field_3: z2VULF, field_4: z2VUSQ, field_5: z2Vb4P, field_6: z2VU7R });
wire_external_newtype!(z2VfEn, std::string::String);
wire_struct!(z2VNoP { field_0: z2VXpH, field_1: z2VdCT, field_2: Vec< z2VQ8r> });
wire_enum!(z2VSL1 { unit { 0 => z2VVrv : "SimpleSelfSigned", 1 => z2VNMk : "ComplexQuorum" } unary {  } });
wire_struct!(z2VWkd { field_0: z2VaDY, field_1: z2VL5X, field_2: z2VMiY, field_3: Option< z2VWd1>, field_4: Option< z2VcHz> });
wire_struct!(z2VMD6 { field_0: z2VWd1, field_1: z2VL5X });
wire_struct!(z2VQss { field_0: z2Vevu, field_1: z2VZZu });
wire_struct!(z2VcBu { field_0: z2Vevu, field_1: z2VcjD });
wire_struct!(z2VYzR { field_0: z2VbEU });
wire_struct!(z2VKzA { field_0: z2VbEU, field_1: z2VWd1 });
wire_struct!(z2VMCk { field_0: z2VMEA, field_1: z2VbxF, field_2: z2VL5X });
wire_struct!(z2VWTR { field_0: z2VUph, field_1: z2VMEA });
wire_struct!(z2VSrE { field_0: z2VcjD, field_1: Vec< z2VZTd>, field_2: z2VYW2, field_3: z2VMiY });
wire_struct!(z2Vedi { field_0: z2VL5X });
wire_struct!(z2VUQg { field_0: z2VUph });
wire_struct!(z2VUSQ { field_0: z2VWd1, field_1: z2VWd1 });
wire_enum!(z2VZih { unit { 0 => z2VYog : "EmptyThreshold", 1 => z2Vd2T : "DuplicatePolicyMember", 3 => z2VMvz : "EmptyConjunction", 4 => z2VZ2M : "ThresholdUnsatisfiable", 5 => z2VNvK : "EmptyDisjunction" } unary { 2 => z2VXDn(z2Vevu) : "DanglingReference" } });
wire_struct!(z2VdbV { field_0: z2VbxF, field_1: z2VdVm });
wire_struct!(z2VbLW { field_0: z2VZMH, field_1: z2VL5X, field_2: z2VPdA, field_3: Option< z2VWd1> });
wire_enum!(z2VSD2 { unit { 0 => z2VVh1 : "CriomeRoot", 1 => z2Vb5d : "HostPublication", 2 => z2VPdE : "ReleaseAuthorization", 3 => z2VZaV : "PersonaRequest", 4 => z2VLEu : "AgentRequest" } unary {  } });
wire_enum!(z2Vb4P { unit { 0 => z2VdJF : "LeaveParked", 1 => z2VY7Y : "AutoReject", 2 => z2Vc1u : "AutoApprove" } unary {  } });
wire_newtype!(z2VY7s, z2VbxF);
wire_external_newtype!(z2VKuU, u64);
wire_enum!(z2VSPF { unit { 0 => z2VY3P : "Approve", 1 => z2VRgx : "Reject" } unary {  } });
wire_external_newtype!(z2VfEW, std::string::String);
wire_struct!(z2VSX9 { field_0: z2VdZJ, field_1: z2VSrv, field_2: z2VZZu, field_3: z2VY7s });
wire_external_newtype!(z2VULF, Vec< z2VfEn>);
wire_enum!(z2VTLE { unit { 0 => z2VYVT : "AutoApprove", 1 => z2VT5C : "ClientApproval", 2 => z2VM5Y : "Quorum" } unary {  } });
wire_struct!(z2VdSM { field_0: z2VWaA, field_1: z2VYW2 });
wire_struct!(z2VWfQ { field_0: z2VQKS });
wire_enum!(z2VMSL { unit { 0 => z2VMmd : "ReplayAttempted", 1 => z2Vbw6 : "UnauthorizedRegistration", 2 => z2VRsT : "OutsideTimeWindow", 3 => z2Ve63 : "StaleVote", 4 => z2VP2T : "UnknownIdentity", 5 => z2VZzA : "ForgedVote", 6 => z2VMNG : "SelfLoopSuccessor", 7 => z2Vc9J : "MalformedRequest", 8 => z2Vcmp : "UnsupportedSignatureScheme", 9 => z2VTcV : "DuplicateIdentity", 10 => z2VeA2 : "RevokedIdentity" } unary {  } });
wire_struct!(z2VVJT { field_0: z2VN9q, field_1: z2VYwG, field_2: z2Vevu, field_3: z2VaDY, field_4: z2VbTN });
wire_enum!(z2VPCX { unit { 0 => z2VZGx : "Bls12_381MinSig", 1 => z2VR7A : "Bls12_381MinPk" } unary {  } });
wire_enum!(z2VRPH { unit { 0 => z2VU2L : "Revoked", 1 => z2Vdf2 : "Active" } unary {  } });
wire_enum!(z2VQce { unit { 0 => z2VcYx : "Rejected", 1 => z2VPH9 : "Approved", 2 => z2VWyL : "LeftParked" } unary {  } });
wire_struct!(z2VW3f { field_0: z2VfEW, field_1: z2VShF, field_2: z2VQce, field_3: z2VMvf, field_4: z2VWd1 });
wire_enum!(z2VYwG { unit { 0 => z2VZBy : "Commit", 1 => z2VTZk : "Request" } unary {  } });
wire_struct!(z2VUEA { field_0: Vec< z2VPN6> });
wire_external_newtype!(z2VMh7, std::string::String);
wire_newtype!(z2VWaA, z2VbxF);
wire_struct!(z2VLMo { field_0: z2VfEW, field_1: z2VShF, field_2: z2Vb3i, field_3: z2VcHz, field_4: z2VWd1, field_5: z2VWd1, field_6: z2Vb4P });
wire_struct!(z2Va2u { field_0: z2VN9q, field_1: z2VYwG, field_2: z2Vevu, field_3: z2VNxH, field_4: z2VUfX, field_5: z2VUfX, field_6: Option< z2VQFm> });
wire_struct!(z2VdVm { field_0: z2VUph, field_1: z2VaDY, field_2: z2VQdW, field_3: z2VUze, field_4: Vec< z2VTRq>, field_5: z2VL5X, field_6: z2VWd1, field_7: Option< z2VWd1> });
wire_struct!(z2VT68 { field_0: Vec< z2VRPv> });
wire_struct!(z2VaZo {  });
wire_external_newtype!(z2VPqc, u64);
wire_struct!(z2VZ96 { field_0: z2Ve1s, field_1: z2VcSh });
wire_struct!(z2VSmP { field_0: z2VL5X, field_1: z2VRPH });
wire_enum!(z2VcSh { unit { 0 => z2VMNo : "SignatureScopeMismatch", 1 => z2VcAF : "SignerUnavailable", 2 => z2VcRP : "RequiredSignatureMissing", 3 => z2VbSC : "SignatureExpired", 4 => z2VQS5 : "SignatureRejected", 5 => z2VPm8 : "PolicyRefused", 6 => z2VMTp : "RequestDigestMismatch", 7 => z2VTz2 : "SignerThresholdRejected" } unary {  } });
wire_struct!(z2Vcoi { field_0: z2VaDY, field_1: z2VL5X, field_2: z2VTRq });
wire_struct!(z2VeNt { field_0: z2Vevu, field_1: z2VaDY, field_2: z2VQFm });
wire_struct!(z2VYWi { field_0: z2VSmP });
wire_enum!(z2VSEb { unit {  } unary { 0 => z2VQPK(z2Vevu) : "ObjectMember", 1 => z2VUAD(z2VL5X) : "KeyMember" } });
wire_struct!(z2VaoB { field_0: z2VL5X, field_1: z2VL5X, field_2: z2VahY, field_3: Option< z2VWd1> });
wire_newtype!(z2Vevu, z2VbxF);
wire_enum!(z2VUze { unit { 0 => z2VRVK : "Expired", 1 => z2VQyk : "Rejected", 2 => z2VUT3 : "PendingSignatures", 3 => z2VTtp : "RequiredSignaturesSatisfied", 4 => z2VVU9 : "SingleSignature" } unary {  } });
wire_external_newtype!(z2VeKX, Vec< z2VfB8>);
wire_external_newtype!(z2Vb3i, std::string::String);
wire_external_newtype!(z2VbzK, std::string::String);
wire_struct!(z2VaDY { field_0: z2VduC, field_1: z2VbxF, field_2: z2VLn9 });
wire_external_newtype!(z2VdCT, std::string::String);
wire_struct!(z2VdFB { field_0: z2VMG4 });
wire_struct!(z2VS8R { field_0: z2VUfX, field_1: z2VUfX });
wire_external_newtype!(z2VMEA, std::string::String);
wire_struct!(z2VL3S { field_0: z2VUfX, field_1: Vec< z2VSEb> });
wire_enum!(z2VSRu { unit { 10 => z2VPyb : "EscalateToPsyche" } unary { 0 => z2Vaoi(z2VT1M) : "Timed", 1 => z2VWtx(Vec< z2Vevu>) : "Any", 2 => z2VR9Q(Vec< z2Vevu>) : "All", 3 => z2VYa2(z2VMD6) : "ActiveAfter", 4 => z2VSy2(z2VL5X) : "SignedBy", 5 => z2Vbxc(z2VVNR) : "Workflow", 6 => z2VPaA(z2VQsx) : "Agreement", 7 => z2VTbM(z2VMD6) : "ActiveUntil", 8 => z2VVb3(z2VRbn) : "Composite", 9 => z2VWTs(z2VL3S) : "ThresholdRule" } });
wire_struct!(z2VS9T { field_0: z2VXpH, field_1: z2VXpH, field_2: Option< z2VXpH>, field_3: Option< z2VdZ4>, field_4: z2VTLE, field_5: Option< z2VL5X>, field_6: Option< z2VNoP>, field_7: Option< z2VUKd> });
wire_struct!(z2VYPy { field_0: Vec< z2VSmP> });
wire_struct!(z2VUZ4 { field_0: z2VMSL });
wire_struct!(z2VeWk { field_0: z2Vbwi });
wire_struct!(z2VTXp { field_0: z2VWaA, field_1: z2VMjw });
wire_struct!(z2VbEU { field_0: z2VZMH, field_1: z2VL5X, field_2: z2VVvg, field_3: z2VWd1, field_4: Option< z2VWd1>, field_5: z2VPdA });
wire_struct!(z2VQKS { field_0: z2VL5X });
wire_struct!(z2VULZ { field_0: Vec< z2VRPv> });
wire_external_newtype!(z2VMbZ, std::string::String);
wire_enum!(z2VahY { unit { 0 => z2Vcbm : "ChannelGrant", 1 => z2VdbS : "SignedObject", 2 => z2VX9u : "ChannelRetract", 3 => z2VeqA : "PrivilegeElevation", 4 => z2VeTG : "Authorization", 5 => z2VMWv : "Archive", 6 => z2VYnt : "ComponentRelease" } unary {  } });
wire_struct!(z2VZMH { field_0: z2VbxF, field_1: z2VahY, field_2: z2VMEA });
wire_struct!(z2VeqE { field_0: z2VPMJ, field_1: Option< z2VL5X>, field_2: Option< z2VWd1> });
wire_struct!(z2VcjD { field_0: z2VSRu, field_1: z2VPjZ });
wire_struct!(z2VPZU { field_0: z2VUph, field_1: z2VbxF, field_2: z2VMh7, field_3: z2VbzK, field_4: z2VeGX, field_5: z2VL5X, field_6: z2VL5X });
wire_external_newtype!(z2VXpH, std::string::String);
wire_struct!(z2VSiq { field_0: z2VUph, field_1: z2VWd1 });
wire_enum!(z2VNxH { unit { 0 => z2VezB : "Authorized", 1 => z2VLZH : "Gathering" } unary {  } });
wire_struct!(z2VNrA { field_0: z2VL5X, field_1: z2VdZ4, field_2: z2VW6A, field_3: z2VSD2, field_4: Option< z2VVvg> });
wire_external_newtype!(z2VU7R, u64);
wire_enum!(z2VN3L { unit {  } unary { 0 => z2VVBx(z2VXnX) : "RouteSignatureRequest", 1 => z2VTRD(z2VWkd) : "AuthorizeSignalCall", 2 => z2VNMG(z2VNJc) : "SubscribeIdentityUpdates", 3 => z2VLca(z2VNrA) : "RegisterIdentity", 4 => z2Vd7d(z2VeNt) : "EvaluateAuthorization", 5 => z2VPYz(z2VdbV) : "VerifyAuthorization", 6 => z2VeHA(z2Vb2e) : "ConveyFounding", 7 => z2VTUZ(z2VVJT) : "ProposeQuorumAuthorization", 8 => z2VYgc(z2VUQg) : "ObserveAuthorization", 9 => z2VaoE(z2VRwp) : "AttestChannelGrant", 10 => z2VWfV(z2Vevu) : "LookupContract", 11 => z2VXxG(z2VL1q) : "SubmitQuorumVote", 12 => z2VcmV(z2VcjD) : "AdmitContract", 13 => z2VQdc(z2VL92) : "ObserveQuorumRound", 14 => z2VTKk(z2VWk3) : "RejectAuthorization", 15 => z2VWcr(z2VVC4) : "ObserveAuthorizedObjects", 16 => z2VQ4b(z2VQcd) : "SolicitQuorumVote", 17 => z2VVGJ(z2Vedi) : "LookupIdentity", 18 => z2VSRJ(z2Vf4i) : "RunDueContractChecks", 19 => z2VXyc(z2VeMQ) : "RevokeIdentity", 20 => z2Vcta(z2Vbwi) : "AuthorizationObservationRetraction", 21 => z2VQa4(z2VdtA) : "ObserveParkedAuthorizations", 22 => z2VRS9(z2VMG4) : "AuthorizedObjectUpdateRetraction", 23 => z2VdX1(z2VaWD) : "AttestArchive", 24 => z2VdAQ(z2VbLW) : "Sign", 25 => z2VNMb(z2VZcV) : "SubmitSignature", 26 => z2VLkL(z2VWVn) : "VerifyAttestation", 27 => z2VXMa(z2VQKS) : "IdentitySubscriptionRetraction", 28 => z2VVWk(z2VQ9E) : "ScheduleContractTimeCheck", 29 => z2VMY4(z2VaZo) : "ObserveNodePublicKey", 30 => z2VSM8(z2VUiL) : "AttestAuthorization" } });
wire_struct!(z2VMs1 { field_0: z2Vevu });
wire_struct!(z2VUjo { field_0: z2Vb3i, field_1: z2VReV, field_2: z2VULF, field_3: z2VPqc, field_4: z2Vb4P, field_5: z2VU7R, field_6: z2VYM1 });
wire_enum!(z2VXKz { unit {  } unary { 0 => z2VZkW(z2Va2u) : "QuorumRoundObserved", 1 => z2VSnP(z2Va2u) : "QuorumVoteAccepted", 2 => z2VUr9(z2VUEA) : "ParkedAuthorizations", 3 => z2VPdb(z2VbP2) : "SignatureRouted", 4 => z2VTBN(z2VeWk) : "AuthorizationObservationClosed", 5 => z2VMWf(z2VYNR) : "PublicKeyObserved", 6 => z2VMZ1(z2VTXp) : "FoundingConveyed", 7 => z2VcLd(z2VdFB) : "AuthorizedObjectRetracted", 8 => z2VLFu(z2VWfQ) : "SubscriptionClosed", 9 => z2VYue(z2VdVm) : "AuthorizationGranted", 10 => z2VL7Z(z2VQ3r) : "ContractAbsent", 11 => z2VLsJ(z2VR27) : "QuorumRefused", 12 => z2VTiL(z2VYzR) : "Attested", 13 => z2Vbqs(z2VeqE) : "Verified", 14 => z2VXKB(z2VUwF) : "Pending", 15 => z2VMj1(z2VUSP) : "AuthorizationObserved", 16 => z2VPpy(z2VWTR) : "Unavailable", 17 => z2Vf9K(z2VWHY) : "Denied", 18 => z2VYbF(z2VSmP) : "IdentityRegistered", 19 => z2Veie(z2VKzA) : "Signed", 20 => z2VSeV(z2VYPy) : "Identities", 21 => z2Vc16(z2VcBu) : "ContractLocated", 22 => z2VPVy(z2VPxW) : "TimeCheckScheduled", 23 => z2VYME(z2VULZ) : "AuthorizedObjectsUpdated", 24 => z2VQJe(z2VWvU) : "ContractRefused", 25 => z2VP3w(z2VQdY) : "SignatureSubmitted", 26 => z2VeMR(z2VQss) : "AuthorizationJudged", 27 => z2VY5A(z2VSiq) : "Expired", 28 => z2VMDs(z2VMs1) : "ContractAccepted", 29 => z2VLmL(z2VT68) : "DueChecksEvaluated", 30 => z2VXcD(z2VUZ4) : "Refused", 31 => z2VQdC(z2Va2u) : "QuorumVoteSolicited", 32 => z2VcFE(z2Va2u) : "QuorumRoundOpened" } });
wire_enum!(z2VPjZ { unit { 0 => z2Vcjw : "Root" } unary { 1 => z2VYj7(z2Vevu) : "Parent" } });
wire_struct!(z2VdtA {  });
wire_struct!(z2VQ9E { field_0: z2Vevu, field_1: z2VWd1, field_2: z2VaDY, field_3: z2VRpF });
wire_newtype!(z2VTuy, z2VbxF);
wire_struct!(z2VQ3r { field_0: z2Vevu });
wire_external_newtype!(z2VeGX, std::string::String);
wire_struct!(z2VaWD { field_0: z2VMCk, field_1: z2VPdA });
wire_external_newtype!(z2VQHy, std::string::String);
wire_struct!(z2VQ8r { field_0: z2VL5X, field_1: z2VdCT });
wire_struct!(z2VPfK { field_0: z2VL5X, field_1: z2VVvg });
wire_enum!(z2VduC { unit { 0 => z2VYQn : "Persona", 1 => z2VMSa : "Router", 2 => z2VemG : "Spirit", 3 => z2VQBv : "Mirror", 4 => z2VPJA : "Agent", 5 => z2VSC3 : "Lojix", 6 => z2Vf2L : "Criome" } unary {  } });
wire_enum!(z2Ve1s { unit { 0 => z2VWaY : "Signers", 1 => z2VdAV : "Policy" } unary {  } });
wire_struct!(z2VQdY { field_0: z2VUph, field_1: z2VL5X });
wire_struct!(z2VUSP { field_0: Vec< z2VQAt> });
wire_struct!(z2VWvU { field_0: z2VZih });
wire_external_newtype!(z2VWd1, u64);
wire_struct!(z2VRAT { field_0: z2VVmW });
wire_struct!(z2VQcd { field_0: z2VN9q, field_1: z2VYwG, field_2: z2Vevu, field_3: z2VaDY, field_4: z2VP1D, field_5: z2VL5X });
wire_struct!(z2VYM8 { field_0: z2VaDY, field_1: Vec< z2VL5X>, field_2: Vec< z2VL5X> });
wire_struct!(z2VReV { field_0: z2VMbZ });
wire_struct!(z2VXnX { field_0: z2VPZU, field_1: z2VL5X });
wire_struct!(z2VYNR { field_0: z2VdZ4 });
wire_external_newtype!(z2VW6A, std::string::String);
wire_struct!(z2VT1M { field_0: z2VWd1, field_1: z2VL3S, field_2: z2VL3S });
wire_struct!(z2VbTN { field_0: z2VWd1, field_1: z2VWd1 });
wire_external_newtype!(z2VShF, std::string::String);
wire_struct!(z2VSGX { field_0: z2VfEW, field_1: z2VSPF });
wire_struct!(z2VXWs { field_0: z2VShF });
wire_struct!(z2Vbwi { field_0: z2VUph });
wire_enum!(z2VYW2 { unit { 0 => z2VVkq : "CriomeRootFoundingV1" } unary {  } });
wire_struct!(z2VRwp { field_0: z2VZMH, field_1: z2VL5X, field_2: z2VPdA });
wire_struct!(z2VM44 { field_0: z2VbxF, field_1: z2VbxF, field_2: z2VL5X, field_3: z2VTRq });

macro_rules! archive_root {
    ($root:ident) => {
        impl Archive for $root {
            type Archived = <WireValue as Archive>::Archived;
            type Resolver = <WireValue as Archive>::Resolver;
            fn resolve(&self, resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
                self.to_wire().resolve(resolver, out);
            }
        }
        impl<Serializer> RkyvSerialize<Serializer> for $root
        where
            Serializer: rkyv::rancor::Fallible + ?Sized,
            WireValue: RkyvSerialize<Serializer>,
        {
            fn serialize(
                &self,
                serializer: &mut Serializer,
            ) -> Result<Self::Resolver, Serializer::Error> {
                self.to_wire().serialize(serializer)
            }
        }
        impl<Deserializer> RkyvDeserialize<$root, Deserializer> for ArchivedWireValue
        where
            Deserializer: rkyv::rancor::Fallible + ?Sized,
            Deserializer::Error: rkyv::rancor::Source,
            ArchivedWireValue: RkyvDeserialize<WireValue, Deserializer>,
        {
            fn deserialize(
                &self,
                deserializer: &mut Deserializer,
            ) -> Result<$root, Deserializer::Error> {
                let wire = <ArchivedWireValue as RkyvDeserialize<
                    WireValue,
                    Deserializer,
                >>::deserialize(self, deserializer)?;
                <$root as WireShape>::from_wire(wire).map_err(Deserializer::Error::new)
            }
        }
    };
}
archive_root!(z2VdZ4);
archive_root!(z2VUiL);
archive_root!(z2VNo7);
archive_root!(z2VUfX);
archive_root!(z2VZZu);
archive_root!(z2VMiY);
archive_root!(z2VcHz);
archive_root!(z2Vbch);
archive_root!(z2VP1D);
archive_root!(z2VSJ5);
archive_root!(z2VTRq);
archive_root!(z2VVC4);
archive_root!(z2VQsx);
archive_root!(z2VYrq);
archive_root!(z2VPDB);
archive_root!(z2VVmW);
archive_root!(z2Vf4i);
archive_root!(z2VRPv);
archive_root!(z2VPMJ);
archive_root!(z2VVvg);
archive_root!(z2VYM1);
archive_root!(z2VVNR);
archive_root!(z2VR27);
archive_root!(z2VVqk);
archive_root!(z2VZjL);
archive_root!(z2VWVn);
archive_root!(z2VPN6);
archive_root!(z2VMG4);
archive_root!(z2VeMQ);
archive_root!(z2VYV1);
archive_root!(z2VNJc);
archive_root!(z2VUwF);
archive_root!(z2Vb2e);
archive_root!(z2VUph);
archive_root!(z2VbxF);
archive_root!(z2VWHY);
archive_root!(z2VZTd);
archive_root!(z2VdKy);
archive_root!(z2Vb3U);
archive_root!(z2VXA2);
archive_root!(z2VWfb);
archive_root!(z2VWk3);
archive_root!(z2VSrv);
archive_root!(z2VPdA);
archive_root!(z2VQY3);
archive_root!(z2VMjw);
archive_root!(z2VQFm);
archive_root!(z2VL92);
archive_root!(z2VM1c);
archive_root!(z2VL5X);
archive_root!(z2VRbn);
archive_root!(z2VSyf);
archive_root!(z2Vd8U);
archive_root!(z2VN9q);
archive_root!(z2VUKd);
archive_root!(z2VbP2);
archive_root!(z2VRpF);
archive_root!(z2VdZJ);
archive_root!(z2VQAt);
archive_root!(z2VPxW);
archive_root!(z2VLn9);
archive_root!(z2VdpP);
archive_root!(z2VZcV);
archive_root!(z2VQdW);
archive_root!(z2VL1q);
archive_root!(z2VMvf);
archive_root!(z2VfB8);
archive_root!(z2VfEn);
archive_root!(z2VNoP);
archive_root!(z2VSL1);
archive_root!(z2VWkd);
archive_root!(z2VMD6);
archive_root!(z2VQss);
archive_root!(z2VcBu);
archive_root!(z2VYzR);
archive_root!(z2VKzA);
archive_root!(z2VMCk);
archive_root!(z2VWTR);
archive_root!(z2VSrE);
archive_root!(z2Vedi);
archive_root!(z2VUQg);
archive_root!(z2VUSQ);
archive_root!(z2VZih);
archive_root!(z2VdbV);
archive_root!(z2VbLW);
archive_root!(z2VSD2);
archive_root!(z2Vb4P);
archive_root!(z2VY7s);
archive_root!(z2VKuU);
archive_root!(z2VSPF);
archive_root!(z2VfEW);
archive_root!(z2VSX9);
archive_root!(z2VULF);
archive_root!(z2VTLE);
archive_root!(z2VdSM);
archive_root!(z2VWfQ);
archive_root!(z2VMSL);
archive_root!(z2VVJT);
archive_root!(z2VPCX);
archive_root!(z2VRPH);
archive_root!(z2VQce);
archive_root!(z2VW3f);
archive_root!(z2VYwG);
archive_root!(z2VUEA);
archive_root!(z2VMh7);
archive_root!(z2VWaA);
archive_root!(z2VLMo);
archive_root!(z2Va2u);
archive_root!(z2VdVm);
archive_root!(z2VT68);
archive_root!(z2VaZo);
archive_root!(z2VPqc);
archive_root!(z2VZ96);
archive_root!(z2VSmP);
archive_root!(z2VcSh);
archive_root!(z2Vcoi);
archive_root!(z2VeNt);
archive_root!(z2VYWi);
archive_root!(z2VSEb);
archive_root!(z2VaoB);
archive_root!(z2Vevu);
archive_root!(z2VUze);
archive_root!(z2VeKX);
archive_root!(z2Vb3i);
archive_root!(z2VbzK);
archive_root!(z2VaDY);
archive_root!(z2VdCT);
archive_root!(z2VdFB);
archive_root!(z2VS8R);
archive_root!(z2VMEA);
archive_root!(z2VL3S);
archive_root!(z2VSRu);
archive_root!(z2VS9T);
archive_root!(z2VYPy);
archive_root!(z2VUZ4);
archive_root!(z2VeWk);
archive_root!(z2VTXp);
archive_root!(z2VbEU);
archive_root!(z2VQKS);
archive_root!(z2VULZ);
archive_root!(z2VMbZ);
archive_root!(z2VahY);
archive_root!(z2VZMH);
archive_root!(z2VeqE);
archive_root!(z2VcjD);
archive_root!(z2VPZU);
archive_root!(z2VXpH);
archive_root!(z2VSiq);
archive_root!(z2VNxH);
archive_root!(z2VNrA);
archive_root!(z2VU7R);
archive_root!(z2VN3L);
archive_root!(z2VMs1);
archive_root!(z2VUjo);
archive_root!(z2VXKz);
archive_root!(z2VPjZ);
archive_root!(z2VdtA);
archive_root!(z2VQ9E);
archive_root!(z2VTuy);
archive_root!(z2VQ3r);
archive_root!(z2VeGX);
archive_root!(z2VaWD);
archive_root!(z2VQHy);
archive_root!(z2VQ8r);
archive_root!(z2VPfK);
archive_root!(z2VduC);
archive_root!(z2Ve1s);
archive_root!(z2VQdY);
archive_root!(z2VUSP);
archive_root!(z2VWvU);
archive_root!(z2VWd1);
archive_root!(z2VRAT);
archive_root!(z2VQcd);
archive_root!(z2VYM8);
archive_root!(z2VReV);
archive_root!(z2VXnX);
archive_root!(z2VYNR);
archive_root!(z2VW6A);
archive_root!(z2VT1M);
archive_root!(z2VbTN);
archive_root!(z2VShF);
archive_root!(z2VSGX);
archive_root!(z2VXWs);
archive_root!(z2Vbwi);
archive_root!(z2VYW2);
archive_root!(z2VRwp);
archive_root!(z2VM44);


pub enum ContractMarker {}

impl signal_frame::WireContract for ContractMarker {
    const BINDING: signal_frame::ContractBinding = signal_frame::ContractBinding::new(
        match signal_frame::ContractId::try_new(3) {
            Ok(value) => value,
            Err(_) => panic!("contract ID is allocated"),
        },
        match signal_frame::WireRevision::try_new(2) {
            Ok(value) => value,
            Err(_) => panic!("wire revision is allocated"),
        },
    );
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineRefusalReason {
    Rejected,
    Unavailable,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct EngineRefusal {
    pub reason: EngineRefusalReason,
    pub detail: std::string::String,
}

impl EngineRefusal {
    pub fn rejected(detail: std::string::String) -> Self {
        Self { reason: EngineRefusalReason::Rejected, detail }
    }

    pub fn unavailable(detail: std::string::String) -> Self {
        Self { reason: EngineRefusalReason::Unavailable, detail }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignalFrameError {
    #[error("failed to encode bound signal frame")]
    FrameEncode,
    #[error("failed to decode bound signal frame")]
    ArchiveDecode,
    #[error("unexpected signal frame body")]
    UnexpectedFrameBody,
    #[error("expected one request operation, found {found}")]
    OperationCount { found: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InputRoute {
    RouteSignatureRequest,
    AuthorizeSignalCall,
    SubscribeIdentityUpdates,
    RegisterIdentity,
    EvaluateAuthorization,
    VerifyAuthorization,
    ConveyFounding,
    ProposeQuorumAuthorization,
    ObserveAuthorization,
    AttestChannelGrant,
    LookupContract,
    SubmitQuorumVote,
    AdmitContract,
    ObserveQuorumRound,
    RejectAuthorization,
    ObserveAuthorizedObjects,
    SolicitQuorumVote,
    LookupIdentity,
    RunDueContractChecks,
    RevokeIdentity,
    AuthorizationObservationRetraction,
    ObserveParkedAuthorizations,
    AuthorizedObjectUpdateRetraction,
    AttestArchive,
    Sign,
    SubmitSignature,
    VerifyAttestation,
    IdentitySubscriptionRetraction,
    ScheduleContractTimeCheck,
    ObserveNodePublicKey,
    AttestAuthorization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OutputRoute {
    QuorumRoundObserved,
    QuorumVoteAccepted,
    ParkedAuthorizations,
    SignatureRouted,
    AuthorizationObservationClosed,
    PublicKeyObserved,
    FoundingConveyed,
    AuthorizedObjectRetracted,
    SubscriptionClosed,
    AuthorizationGranted,
    ContractAbsent,
    QuorumRefused,
    Attested,
    Verified,
    Pending,
    AuthorizationObserved,
    Unavailable,
    Denied,
    IdentityRegistered,
    Signed,
    Identities,
    ContractLocated,
    TimeCheckScheduled,
    AuthorizedObjectsUpdated,
    ContractRefused,
    SignatureSubmitted,
    AuthorizationJudged,
    Expired,
    ContractAccepted,
    DueChecksEvaluated,
    Refused,
    QuorumVoteSolicited,
    QuorumRoundOpened,
}

impl z2VN3L {
    pub fn route(&self) -> InputRoute {
        match self {
            Self::z2VVBx(_) => InputRoute::RouteSignatureRequest,
            Self::z2VTRD(_) => InputRoute::AuthorizeSignalCall,
            Self::z2VNMG(_) => InputRoute::SubscribeIdentityUpdates,
            Self::z2VLca(_) => InputRoute::RegisterIdentity,
            Self::z2Vd7d(_) => InputRoute::EvaluateAuthorization,
            Self::z2VPYz(_) => InputRoute::VerifyAuthorization,
            Self::z2VeHA(_) => InputRoute::ConveyFounding,
            Self::z2VTUZ(_) => InputRoute::ProposeQuorumAuthorization,
            Self::z2VYgc(_) => InputRoute::ObserveAuthorization,
            Self::z2VaoE(_) => InputRoute::AttestChannelGrant,
            Self::z2VWfV(_) => InputRoute::LookupContract,
            Self::z2VXxG(_) => InputRoute::SubmitQuorumVote,
            Self::z2VcmV(_) => InputRoute::AdmitContract,
            Self::z2VQdc(_) => InputRoute::ObserveQuorumRound,
            Self::z2VTKk(_) => InputRoute::RejectAuthorization,
            Self::z2VWcr(_) => InputRoute::ObserveAuthorizedObjects,
            Self::z2VQ4b(_) => InputRoute::SolicitQuorumVote,
            Self::z2VVGJ(_) => InputRoute::LookupIdentity,
            Self::z2VSRJ(_) => InputRoute::RunDueContractChecks,
            Self::z2VXyc(_) => InputRoute::RevokeIdentity,
            Self::z2Vcta(_) => InputRoute::AuthorizationObservationRetraction,
            Self::z2VQa4(_) => InputRoute::ObserveParkedAuthorizations,
            Self::z2VRS9(_) => InputRoute::AuthorizedObjectUpdateRetraction,
            Self::z2VdX1(_) => InputRoute::AttestArchive,
            Self::z2VdAQ(_) => InputRoute::Sign,
            Self::z2VNMb(_) => InputRoute::SubmitSignature,
            Self::z2VLkL(_) => InputRoute::VerifyAttestation,
            Self::z2VXMa(_) => InputRoute::IdentitySubscriptionRetraction,
            Self::z2VVWk(_) => InputRoute::ScheduleContractTimeCheck,
            Self::z2VMY4(_) => InputRoute::ObserveNodePublicKey,
            Self::z2VSM8(_) => InputRoute::AttestAuthorization,
        }
    }

    pub fn wire_route(&self) -> signal_frame::WireRoute {
        signal_frame::WireRoute::new(
            signal_frame::RootCode::new(0),
            signal_frame::VariantCode::new(self.route() as u8),
        )
    }

    pub fn into_frame(self, exchange: signal_frame::ExchangeIdentifier) -> Frame {
        let route = self.wire_route();
        Frame::new(
            route,
            FrameBody::Request {
                exchange,
                request: signal_frame::Request::from_payload(self),
            },
        )
    }

    pub fn encode_request_frame(
        self,
        exchange: signal_frame::ExchangeIdentifier,
    ) -> Result<Vec<u8>, SignalFrameError> {
        self.into_frame(exchange)
            .encode()
            .map_err(|_| SignalFrameError::FrameEncode)
    }
}

impl z2VXKz {
    pub fn route(&self) -> OutputRoute {
        match self {
            Self::z2VZkW(_) => OutputRoute::QuorumRoundObserved,
            Self::z2VSnP(_) => OutputRoute::QuorumVoteAccepted,
            Self::z2VUr9(_) => OutputRoute::ParkedAuthorizations,
            Self::z2VPdb(_) => OutputRoute::SignatureRouted,
            Self::z2VTBN(_) => OutputRoute::AuthorizationObservationClosed,
            Self::z2VMWf(_) => OutputRoute::PublicKeyObserved,
            Self::z2VMZ1(_) => OutputRoute::FoundingConveyed,
            Self::z2VcLd(_) => OutputRoute::AuthorizedObjectRetracted,
            Self::z2VLFu(_) => OutputRoute::SubscriptionClosed,
            Self::z2VYue(_) => OutputRoute::AuthorizationGranted,
            Self::z2VL7Z(_) => OutputRoute::ContractAbsent,
            Self::z2VLsJ(_) => OutputRoute::QuorumRefused,
            Self::z2VTiL(_) => OutputRoute::Attested,
            Self::z2Vbqs(_) => OutputRoute::Verified,
            Self::z2VXKB(_) => OutputRoute::Pending,
            Self::z2VMj1(_) => OutputRoute::AuthorizationObserved,
            Self::z2VPpy(_) => OutputRoute::Unavailable,
            Self::z2Vf9K(_) => OutputRoute::Denied,
            Self::z2VYbF(_) => OutputRoute::IdentityRegistered,
            Self::z2Veie(_) => OutputRoute::Signed,
            Self::z2VSeV(_) => OutputRoute::Identities,
            Self::z2Vc16(_) => OutputRoute::ContractLocated,
            Self::z2VPVy(_) => OutputRoute::TimeCheckScheduled,
            Self::z2VYME(_) => OutputRoute::AuthorizedObjectsUpdated,
            Self::z2VQJe(_) => OutputRoute::ContractRefused,
            Self::z2VP3w(_) => OutputRoute::SignatureSubmitted,
            Self::z2VeMR(_) => OutputRoute::AuthorizationJudged,
            Self::z2VY5A(_) => OutputRoute::Expired,
            Self::z2VMDs(_) => OutputRoute::ContractAccepted,
            Self::z2VLmL(_) => OutputRoute::DueChecksEvaluated,
            Self::z2VXcD(_) => OutputRoute::Refused,
            Self::z2VQdC(_) => OutputRoute::QuorumVoteSolicited,
            Self::z2VcFE(_) => OutputRoute::QuorumRoundOpened,
        }
    }

    pub fn wire_route(&self) -> signal_frame::WireRoute {
        signal_frame::WireRoute::new(
            signal_frame::RootCode::new(1),
            signal_frame::VariantCode::new(self.route() as u8),
        )
    }

    pub fn into_reply_frame(self, exchange: signal_frame::ExchangeIdentifier) -> Frame {
        let route = self.wire_route();
        let reply = signal_frame::Reply::committed(
            signal_frame::NonEmpty::single(signal_frame::SubReply::Ok(self)),
        );
        Frame::new(route, FrameBody::Reply { exchange, reply })
    }

    pub fn encode_reply_frame(
        self,
        exchange: signal_frame::ExchangeIdentifier,
    ) -> Result<Vec<u8>, SignalFrameError> {
        self.into_reply_frame(exchange)
            .encode()
            .map_err(|_| SignalFrameError::FrameEncode)
    }
}

impl signal_frame::RequestPayload for z2VN3L {}

impl signal_frame::SignalOperationHeads for z2VN3L {
    const HEADS: &'static [&'static str] = &["RouteSignatureRequest", "AuthorizeSignalCall", "SubscribeIdentityUpdates", "RegisterIdentity", "EvaluateAuthorization", "VerifyAuthorization", "ConveyFounding", "ProposeQuorumAuthorization", "ObserveAuthorization", "AttestChannelGrant", "LookupContract", "SubmitQuorumVote", "AdmitContract", "ObserveQuorumRound", "RejectAuthorization", "ObserveAuthorizedObjects", "SolicitQuorumVote", "LookupIdentity", "RunDueContractChecks", "RevokeIdentity", "AuthorizationObservationRetraction", "ObserveParkedAuthorizations", "AuthorizedObjectUpdateRetraction", "AttestArchive", "Sign", "SubmitSignature", "VerifyAttestation", "IdentitySubscriptionRetraction", "ScheduleContractTimeCheck", "ObserveNodePublicKey", "AttestAuthorization"];
}

impl signal_frame::LogVariant for z2VN3L {
    fn log_variant(&self) -> u64 {
        let route = self.wire_route();
        u64::from(route.root().value()) | (u64::from(route.variant().value()) << 8)
    }
}

pub type Frame = signal_frame::BoundExchangeFrame<ContractMarker, z2VN3L, z2VXKz>;
pub type FrameBody = signal_frame::ExchangeFrameBody<z2VN3L, z2VXKz>;
pub type Request = signal_frame::Request<z2VN3L>;
pub type ReplyEnvelope = signal_frame::Reply<z2VXKz>;
pub type RequestBuilder = signal_frame::RequestBuilder<z2VN3L>;

impl ContractMarker {
    pub fn decode_frame(bytes: &[u8]) -> Result<Frame, SignalFrameError> {
        Frame::decode(bytes).map_err(|_| SignalFrameError::ArchiveDecode)
    }

    pub fn decode_single_request(
        bytes: &[u8],
    ) -> Result<(signal_frame::ExchangeIdentifier, z2VN3L), SignalFrameError> {
        match Self::decode_frame(bytes)?.into_body() {
            FrameBody::Request { exchange, request } => {
                let found = request.payloads().len();
                if found != 1 {
                    return Err(SignalFrameError::OperationCount { found });
                }
                Ok((exchange, request.payloads.into_head()))
            }
            _ => Err(SignalFrameError::UnexpectedFrameBody),
        }
    }
}
