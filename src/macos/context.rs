use super::sec_sys::*;
use crate::Name;
use std::collections::HashMap;

pub struct Context {
    cert: SecCertificate,
    dict: CFDictionary<CFString, CFDictionary<CFString, CFType>>,
    all: CFDictionary,
}

enum SecProperty {
    Value,
    Label,
    Type,
}

enum SecOID {
    SubjectName,
    IssuerName,
    Serial,

    Country,
    CommonName,
    OrgUnit,
    Org,
}

impl Into<CFString> for SecProperty {
    fn into(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                SecProperty::Value => kSecPropertyKeyValue,
                SecProperty::Label => kSecPropertyKeyLabel,
                SecProperty::Type => kSecPropertyKeyType,
            })
        }
    }
}

impl SecProperty {
    fn to_cfstr(self) -> CFString {
        self.into()
    }
}

impl Into<CFString> for SecOID {
    fn into(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                SecOID::SubjectName => kSecOIDX509V1SubjectName,
                SecOID::IssuerName => kSecOIDX509V1IssuerName,
                SecOID::Serial => kSecOIDX509V1SerialNumber,

                SecOID::CommonName => kSecOIDCommonName,
                SecOID::Country => kSecOIDCountryName,
                SecOID::Org => kSecOIDOrganizationName,
                SecOID::OrgUnit => kSecOIDOrganizationalUnitName,
            })
        }
    }
}

impl Context {
    pub fn new(cert: SecCertificateRef, all: CFDictionary) -> Self {
        Context {
            cert: unsafe { SecCertificate::wrap_under_get_rule(cert) },
            dict: unsafe {
                CFDictionary::wrap_under_create_rule(SecCertificateCopyValues(
                    cert,
                    std::ptr::null(),
                    None,
                ))
            },
            all,
        }
    }

    fn get<T: Into<CFString>>(&self, key: T, wanted_kind: CFString) -> Option<CFType> {
        unsafe {
            let dict = self.dict.find(key.into())?;
            let kind = dict.find(SecProperty::Type.to_cfstr())?;

            if CFString::wrap_under_get_rule(kind.as_CFTypeRef() as _) != wanted_kind {
                return None;
            }

            let value = dict.find(SecProperty::Value.to_cfstr())?;
            Some(CFType::wrap_under_get_rule(value.as_CFTypeRef()))
        }
    }

    fn get_as_section<T: Into<CFString>>(&self, key: T) -> Option<CFArray> {
        unsafe {
            self.get(key, CFString::new("section"))
                .map(|v| CFArray::wrap_under_get_rule(v.as_CFTypeRef() as _))
        }
    }

    fn get_as_string<T: Into<CFString>>(&self, key: T) -> Option<CFString> {
        unsafe {
            self.get(key, CFString::new("string"))
                .map(|v| CFString::wrap_under_get_rule(v.as_CFTypeRef() as _))
        }
    }

    unsafe fn get_sub_value<T: Into<CFString>>(
        values: &CFArray,
        concrete_label: T,
    ) -> Option<CFType> {
        let search_label = concrete_label.into();

        for value in values.iter() {
            // Iterate over the values until we find the correct label
            let subdict: CFDictionary<CFString, CFType> =
                CFDictionary::wrap_under_get_rule(*value as _);

            let label_key: CFString = SecProperty::Label.into();
            let value_key: CFString = SecProperty::Value.into();

            let label = CFString::wrap_under_get_rule(subdict.find(label_key)?.as_CFTypeRef() as _);

            if label == search_label {
                return subdict
                    .find(value_key)
                    .map(|r| CFType::wrap_under_get_rule(r.as_CFTypeRef()));
            }
        }
        None
    }

    unsafe fn get_string<T: Into<CFString>>(values: &CFArray, concrete_label: T) -> Option<String> {
        Self::get_sub_value(values, concrete_label)
            .map(|t| CFString::wrap_under_get_rule(t.as_CFTypeRef() as _).to_string())
    }

    fn name_for_field(&self, field: SecOID) -> Name {
        use SecOID::*;

        let vals = self.get_as_section(field);
        unsafe {
            Name {
                common_name: vals.as_ref().and_then(|a| Self::get_string(&a, CommonName)),
                country: vals.as_ref().and_then(|a| Self::get_string(&a, Country)),
                organization: vals.as_ref().and_then(|a| Self::get_string(&a, Org)),
                organization_unit: vals.as_ref().and_then(|a| Self::get_string(&a, OrgUnit)),
            }
        }
    }

    pub fn serial(&self) -> Option<String> {
        self.get_as_string(SecOID::Serial).map(|s| s.to_string())
    }

    pub fn subject_name(&self) -> Name {
        self.name_for_field(SecOID::SubjectName)
    }

    pub fn issuer_name(&self) -> Name {
        self.name_for_field(SecOID::IssuerName)
    }

    pub fn sha256_thumbprint(&self) -> String {
        let cert_data = unsafe {
            CFData::wrap_under_create_rule(SecCertificateCopyData(self.cert.as_concrete_TypeRef()))
        };

        use sha2::Digest;
        let hash = sha2::Sha256::digest(cert_data.bytes());

        hash.as_slice()
            .iter()
            .fold(String::new(), |s, byte| s + &format!("{:02x}", byte))
    }

    fn team_id(&self) -> Option<String> {
        let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoTeamIdentifier) };
        let value_ref = self.all.find(key.as_CFTypeRef())?;
        let team_id = unsafe { CFString::wrap_under_get_rule(*value_ref as _) };
        return Some(team_id.to_string());
    }

    fn cd_hash(&self) -> Option<String> {
        let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoUnique) };
        let value_ref = self.all.find(key.as_CFTypeRef())?;
        let value = unsafe { CFData::wrap_under_get_rule(*value_ref as _) };
        let hex = value
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        Some(hex)
    }

    fn info_plist(&self) -> Option<CFDictionary> {
        let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoPList) };
        let value_ref = self.all.find(key.as_CFTypeRef())?;
        let value = unsafe { CFDictionary::wrap_under_get_rule(*value_ref as _) };
        Some(value)
    }

    fn key(&self, dict: &CFDictionary, key: &str) -> Option<String> {
        let key = CFString::new(key);
        let value_ref = dict.find(key.as_CFTypeRef())?;
        let value = unsafe { CFString::wrap_under_get_rule(*value_ref as _) };
        Some(value.to_string())
    }

    pub fn additional_properties(&self) -> Option<HashMap<String, String>> {
        let cd_hash = self.cd_hash()?;
        let info_plist = self.info_plist();
        let team_id = self.team_id();
        let mut ret = HashMap::new();
        if let Some(info_plist) = info_plist {
            let bundle_id = self.key(&info_plist, "CFBundleIdentifier");
            let short_version = self.key(&info_plist, "CFBundleShortVersionString");
            let bundle_version = self.key(&info_plist, "CFBundleVersion");
            if let Some(bundle_id) = bundle_id {
                ret.insert("bundle_id".to_string(), bundle_id);
            }
            if let Some(short_version) = short_version {
                ret.insert("short_version".to_string(), short_version);
            }
            if let Some(bundle_version) = bundle_version {
                ret.insert("bundle_version".to_string(), bundle_version);
            }
        }
        if let Some(team_id) = team_id {
            ret.insert("team_id".to_string(), team_id);
        }
        ret.insert("cd_hash".to_string(), cd_hash);
        Some(ret)
    }
}
