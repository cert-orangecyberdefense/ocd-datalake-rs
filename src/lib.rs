mod setting;

use std::collections::{BTreeMap, HashMap};
use reqwest::blocking::Client;
use serde_json::{json, Value};
pub use crate::setting::{DatalakeSetting, RoutesSetting};

#[derive(Clone, Debug)]
pub struct Datalake {
    settings: DatalakeSetting,
    username: String,
    password: String,
    client: Client,
    access_token: Option<String>,
}

impl Datalake {
    pub fn new(username: String, password: String, settings: DatalakeSetting) -> Self {
        Datalake {
            settings,
            username,
            password,
            client: Client::new(),
            access_token: None,
        }
    }
    // TODO handle expired access / refresh token
    fn retrieve_api_token(&self) -> String {
        let mut token = "Token ".to_string();

        let auth_request = self.client.post(&self.settings.routes().authentication);
        let mut json_body = HashMap::new();
        json_body.insert("email", &self.username);
        json_body.insert("password", &self.password);
        let json_resp = match auth_request.json(&json_body).send() {
            Ok(resp) => { resp.json::<Value>().unwrap() }
            Err(err) => { panic!("Could not fetch API {:?}: {:?}", &self.settings.routes().authentication, err); }
        };
        let raw_token = json_resp["access_token"].as_str().unwrap();
        token.push_str(raw_token);
        token
    }

    /// Cached version of retrieve_api_token that return a new token only if needed
    pub fn get_token(&mut self) -> String {
        if self.access_token.is_none() {
            self.access_token = Some(self.retrieve_api_token());
        }
        let token = self.access_token.as_ref().unwrap().clone();
        token
    }

    /// Return the atom types based on the given atom_values
    pub fn extract_atom_type(&mut self, atom_values: &[String]) -> BTreeMap<String, String> {
        let url = self.settings.routes().atom_values_extract.clone();
        let mut request = self.client.post(&url);
        request = request.header("Authorization", self.get_token());
        let mut joined_atom_values = String::from(&atom_values[0]);
        for value in atom_values.iter().skip(1) {
            joined_atom_values.push(' ');
            joined_atom_values.push_str(value);
        }
        let json_body = json!({
            "content": joined_atom_values,
        });
        let json_resp = match request.json(&json_body).send() {
            Ok(resp) => { resp.json::<Value>().unwrap() }
            Err(err) => { panic!("Could not fetch API {:?}: {:?}", &url, err); }
        };
        let results_value = json_resp.get("results").expect("results key not returned by the API");
        let results = results_value.as_object().expect("result key not as expected");  // TODO test empty map
        let mut extracted_atom_types = BTreeMap::new();
        for (atom_type, atoms) in results {
            for atom in atoms.as_array().unwrap() {
                let atom_value = atom.as_str().unwrap().to_string();
                extracted_atom_types.insert(atom_value, atom_type.clone());
            }
        }
        extracted_atom_types
    }

    /// Return a CSV of the bulk lookup for given threats
    ///
    /// Threats have their atom type automatically defined (with hash meaning a File type)
    pub fn bulk_lookup(&mut self, atom_values: Vec<String>) -> String {
        // let mut result = Vec::new();
        //
        // let mut offset = 0;
        // let mut pagination_done = false;
        // while !pagination_done {  // Stop when all subcategories have been retrieved
        //     let token = self.get_token();
        //     let mut request = self.client.post(&self.settings.threat_library_url);
        //     request = request.header("Authorization", token);
        //     let json_body = json!({
        //         "limit": API_MAX_PAGINATION_LIMIT,
        //         "offset": offset,
        //     });
        //     let json_resp = match request.json(&json_body).send() {
        //         Ok(resp) => { resp.json::<Value>().unwrap() }
        //         Err(err) => { panic!("Could not fetch API {:?}: {:?}", &self.settings.threat_library_url, err); }
        //     };
        //
        //     let response = json_resp.as_object().expect(&*format!("Unexpected api response {:?}", json_resp));
        //     let subcategories = response["results"].as_array().unwrap();
        //     for subcategory in subcategories.iter() {
        //         offset += 1;
        //         let tags = subcategory["tags"].as_array().unwrap();
        //         for tag in tags {
        //             result.push(Tag::new(
        //                 tag.as_str().unwrap().to_string(),
        //                 subcategory["category_name"].as_str().unwrap().to_string(),
        //                 subcategory["name"].as_str().unwrap().to_string(),
        //             ));
        //         }
        //     }
        //
        //     let count = response["count"].as_u64().unwrap();
        //     pagination_done = offset >= count;
        // }
        // result
        return "".to_string();
    }
}

#[cfg(test)]
mod tests {
    use crate::{Datalake, DatalakeSetting};

    #[test]
    fn test_create_datalake_with_prod_config() {
        let dtl = Datalake::new(
            "username".to_string(),
            "password".to_string(),
            DatalakeSetting::prod(),
        );

        assert_eq!(dtl.settings.routes().authentication, "https://datalake.cert.orangecyberdefense.com/api/v2/auth/token/");
    }

    #[test]
    fn test_create_datalake_preprod_config() {
        let preprod_setting = DatalakeSetting::preprod();

        let dtl = Datalake::new(
            "username".to_string(),
            "password".to_string(),
            preprod_setting,
        );

        assert_eq!(dtl.settings.routes().authentication, "https://ti.extranet.mrti-center.com/api/v2/auth/token/");
    }
}