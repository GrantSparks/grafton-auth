mod user;
#[cfg(feature = "rbac")]
pub use user::Role;
pub use user::User;

pub trait Identifiable<Id> {
    fn id(&self) -> Id;
}
