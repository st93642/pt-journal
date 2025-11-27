pub mod subdomain_enumeration;
pub mod dns_enumeration;
pub mod port_scanning;
pub mod service_enumeration;
pub mod web_technology_fingerprinting;
pub mod web_crawling_spidering;
pub mod tls_ssl_assessment;
pub mod infrastructure_mapping;
pub mod cloud_asset_discovery;
pub mod email_reconnaissance;
pub mod screenshot_capture;
pub mod javascript_analysis;
pub mod parameter_discovery;
pub mod public_exposure_scanning;
pub mod whois_domain_analysis;
pub mod social_media_reconnaissance;

pub use subdomain_enumeration::SUBDOMAIN_ENUMERATION_STEPS;
pub use dns_enumeration::DNS_ENUMERATION_STEPS;
pub use port_scanning::PORT_SCANNING_STEPS;
pub use service_enumeration::SERVICE_ENUMERATION_STEPS;
pub use web_technology_fingerprinting::WEB_TECHNOLOGY_FINGERPRINTING_STEPS;
pub use web_crawling_spidering::WEB_CRAWLING_SPIDERING_STEPS;
pub use tls_ssl_assessment::TLS_SSL_ASSESSMENT_STEPS;
pub use infrastructure_mapping::INFRASTRUCTURE_MAPPING_STEPS;
pub use cloud_asset_discovery::CLOUD_ASSET_DISCOVERY_STEPS;
pub use email_reconnaissance::EMAIL_RECONNAISSANCE_STEPS;
pub use screenshot_capture::SCREENSHOT_CAPTURE_STEPS;
pub use javascript_analysis::JAVASCRIPT_ANALYSIS_STEPS;
pub use parameter_discovery::PARAMETER_DISCOVERY_STEPS;
pub use public_exposure_scanning::PUBLIC_EXPOSURE_SCANNING_STEPS;
pub use whois_domain_analysis::WHOIS_DOMAIN_ANALYSIS_STEPS;
pub use social_media_reconnaissance::SOCIAL_MEDIA_RECONNAISSANCE_STEPS;

use crate::model::Step;
use uuid::Uuid;

pub const RECONNAISSANCE_STEPS: &[(&str, &str)] = &[
    SUBDOMAIN_ENUMERATION_STEPS[0],
    DNS_ENUMERATION_STEPS[0],
    PORT_SCANNING_STEPS[0],
    SERVICE_ENUMERATION_STEPS[0],
    WEB_TECHNOLOGY_FINGERPRINTING_STEPS[0],
    WEB_CRAWLING_SPIDERING_STEPS[0],
    TLS_SSL_ASSESSMENT_STEPS[0],
    INFRASTRUCTURE_MAPPING_STEPS[0],
    CLOUD_ASSET_DISCOVERY_STEPS[0],
    EMAIL_RECONNAISSANCE_STEPS[0],
    SCREENSHOT_CAPTURE_STEPS[0],
    JAVASCRIPT_ANALYSIS_STEPS[0],
    PARAMETER_DISCOVERY_STEPS[0],
    PUBLIC_EXPOSURE_SCANNING_STEPS[0],
    WHOIS_DOMAIN_ANALYSIS_STEPS[0],
    SOCIAL_MEDIA_RECONNAISSANCE_STEPS[0],
];

/// Create reconnaissance tutorial steps
pub fn create_reconnaissance_steps() -> Vec<Step> {
    RECONNAISSANCE_STEPS
        .iter()
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec!["recon".to_string()],
            )
        })
        .collect()
}
