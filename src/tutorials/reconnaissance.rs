pub mod subdomain_enumeration;
pub mod dns_enumeration;
pub mod port_scanning;
pub mod service_enumeration;

pub use subdomain_enumeration::SUBDOMAIN_ENUMERATION_STEPS;
pub use dns_enumeration::DNS_ENUMERATION_STEPS;
pub use port_scanning::PORT_SCANNING_STEPS;
pub use service_enumeration::SERVICE_ENUMERATION_STEPS;

pub const RECONNAISSANCE_STEPS: &[(&str, &str)] = &[
    SUBDOMAIN_ENUMERATION_STEPS[0],
    DNS_ENUMERATION_STEPS[0],
    PORT_SCANNING_STEPS[0],
    SERVICE_ENUMERATION_STEPS[0],
    // TODO: Add remaining steps from reconnaissance_old.rs
];
