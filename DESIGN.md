## Why two separate brute-force detectors?

Attackers don't all behave the same way. A naive brute-force script tries many passwords as fast as possible, this shows up as a burst of failed attempts in a very short window (e.g. 5+ failures in 60 seconds). As a more obvious aggressive attack, while the low and slow detector spreads attempts out over hours (e.g. 15+ failures across 24 hours), staying under any short-window threshold. 

A single detector tuned for one pattern misses the other. Rather than picking one threshold and hoping it catches everthing, sshwatch runs two independent sliding-window checks in parallel: a tight, fast-burst detector (`detect_brute_force`) and a longer, patient-attacker detector (`detect_low_and_slow_attacks`). Both share the same underlying sliding-window algorithm (`_detect_attempts_in_window`), just parametized differently - this keeps the detection logic itself simple and avoid duplicating the (fiddly) window-management code. 

## Why a sliding window instead of a total count?

Counting total failed attempts per IP doesn't capture *when* those happened only how many. Two failed attempts an hour apart and two attempts two seconds apart would count the same, even though only one of those looks like an attack. 

A sliding window tracks both the count and the timing together: it only flags an IP once a certain number of failures have happened within a specific span of time. This lets the tool distinguish a real attack from unrelated failures that happen to add up ove a long period (e.g. a user mistyping their password once a week for a month shouldn't be the same as 5 failed logins in 10 seconds). 

## Compromise detection 
`find_compromise_alerts` looks for a specific suspicious sequence: several failed login attempts from the same IP, followed by a *successful* login shortly afterward (within `COMPROMISE_LOOKAHEAD_SECONDS`). A lone successful login is normal that's just someone logging in. But several failures immediately followed by a success looks like a brute-force attempt that worked, or an attacker who eventually guessed the right credentials. 

This is arguably the most actionable finding the tool produces: a brute-force burst is a warning, but a compromise alert means an account may already be under attacker control and needs immediate response (forced password reset, session invalidation, etc.).

## Why MITRE ATTACK mapping?
Rathe rthan labeling finding with ad-hoc terms like "brute force" or "compromise" each finding is tagged with a MITRE ATTACK technique is a widley used, standardized framework for describing attacker behaviour SIEMs, threat intel feeds, and security teams all use this shared vocabulary. 

Tagging findings this way does two things: it gives each finding a precise industry-recognized meaning instead of a project-specific label, and connects sshwatch's output to the roader threat landscape rather than treating each detection as an isolated, one-off signal. 

