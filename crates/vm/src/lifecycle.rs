//! A VM's lifecycle as a pure state machine. The runner feeds it what the
//! guest and libkrun report and asks it before acting (a pause only from
//! ready, a resume only from paused); anything else is refused, typed.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum State {
    /// Configured, not yet running.
    Created,
    /// libkrun is running; the guest has not said hello.
    Booting,
    /// The guest said hello and has its start; not yet ready.
    Starting,
    Ready,
    Paused,
    /// The entrypoint exited; the guest is powering off.
    Exited { code: Option<i32>, signal: Option<i32> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Launched,
    Hello,
    Ready,
    Paused,
    Resumed,
    Exited { code: Option<i32>, signal: Option<i32> },
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("{event:?} is not allowed while {state:?}")]
pub struct LifecycleError {
    pub state: State,
    pub event: Event,
}

#[derive(Debug)]
pub struct Lifecycle {
    state: State,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Lifecycle { state: State::Created }
    }
}

impl Lifecycle {
    pub fn new() -> Lifecycle {
        Lifecycle::default()
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// The state after `event`, or a refusal that leaves the state as it was.
    pub fn step(&mut self, event: Event) -> Result<State, LifecycleError> {
        let next = match (self.state, event) {
            (State::Created, Event::Launched) => State::Booting,
            (State::Booting, Event::Hello) => State::Starting,
            (State::Starting, Event::Ready) => State::Ready,
            (State::Ready, Event::Paused) => State::Paused,
            (State::Paused, Event::Resumed) => State::Ready,
            // A paused guest runs nothing, so it cannot report an exit.
            (State::Booting | State::Starting | State::Ready, Event::Exited { code, signal }) => {
                State::Exited { code, signal }
            }
            (state, event) => return Err(LifecycleError { state, event }),
        };
        self.state = next;
        Ok(next)
    }

    /// Whether a pause may be asked of libkrun now.
    pub fn may_pause(&self) -> Result<(), LifecycleError> {
        match self.state {
            State::Ready => Ok(()),
            state => Err(LifecycleError { state, event: Event::Paused }),
        }
    }

    pub fn may_resume(&self) -> Result<(), LifecycleError> {
        match self.state {
            State::Paused => Ok(()),
            state => Err(LifecycleError { state, event: Event::Resumed }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: the path a healthy VM takes is allowed, step by step.
    #[test]
    fn valid_path() {
        let mut l = Lifecycle::new();
        for (e, s) in [
            (Event::Launched, State::Booting),
            (Event::Hello, State::Starting),
            (Event::Ready, State::Ready),
            (Event::Paused, State::Paused),
            (Event::Resumed, State::Ready),
            (Event::Exited { code: Some(0), signal: None }, State::Exited { code: Some(0), signal: None }),
        ] {
            assert_eq!(l.step(e), Ok(s));
        }
    }

    // Goal: each event out of place is refused and changes nothing.
    #[test]
    fn invalid_refused() {
        let mut l = Lifecycle::new();
        assert!(l.step(Event::Ready).is_err());
        assert!(l.may_pause().is_err());
        l.step(Event::Launched).unwrap();
        assert!(l.step(Event::Launched).is_err());
        assert!(l.step(Event::Ready).is_err(), "ready before hello");
        l.step(Event::Hello).unwrap();
        assert!(l.step(Event::Hello).is_err(), "a second hello");
        assert!(l.may_pause().is_err(), "a pause before ready");
        l.step(Event::Ready).unwrap();
        assert!(l.may_resume().is_err());
        l.may_pause().unwrap();
        l.step(Event::Paused).unwrap();
        assert!(l.step(Event::Paused).is_err());
        assert!(l.step(Event::Exited { code: Some(1), signal: None }).is_err(), "a paused guest cannot exit");
        assert_eq!(l.state(), State::Paused);
        l.may_resume().unwrap();
    }

    #[test]
    fn exit_while_booting() {
        let mut l = Lifecycle::new();
        l.step(Event::Launched).unwrap();
        assert_eq!(
            l.step(Event::Exited { code: None, signal: Some(9) }),
            Ok(State::Exited { code: None, signal: Some(9) })
        );
        assert!(l.step(Event::Ready).is_err());
    }
}
