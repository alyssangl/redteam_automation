"""Offline tests for the docker-group privilege-escalation vector.

The privesc stage is prompt-driven, but two seams are pure/deterministic and
testable without a lab:

  - _user_in_docker_group: feasibility — is the shell user in the docker group
    (the precondition that makes the docker breakout the PREFERRED root vector)?
  - _extract_privesc_findings: classifier — a plan describing a docker breakout
    must classify as the `docker_group` technique slug (and the existing
    suid/sudo/kernel classifications must NOT regress).
  - _plan_mentions_docker: gate for the critic's docker-specific rootbash probe.
  - the prompts / mitre catalog carry the docker vector.

No lab needed (lazy MSF). Run: python tests/test_privesc_docker.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stages.privesc as pe
from core_agents import mitre


# --- _user_in_docker_group (feasibility) -------------------------------------

# the real live-run `id` output from boba_fett on Metasploitable 3
_BOBA_ID = "uid=1121(boba_fett) gid=100(users) groups=100(users),999(docker)"


def test_docker_feasible_from_real_id_output():
    assert pe._user_in_docker_group(_BOBA_ID) is True


def test_docker_feasible_gid_form():
    assert pe._user_in_docker_group("uid=1000(x) gid=999(docker) groups=999(docker)") is True


def test_docker_feasible_groups_command_output():
    # bare `groups` command output: space-separated names
    assert pe._user_in_docker_group("users docker sudo") is True


def test_docker_feasible_enumerator_summary_line():
    assert pe._user_in_docker_group("Docker group: YES (user in docker group)") is True


def test_not_in_docker_group_is_infeasible():
    assert pe._user_in_docker_group(
        "uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant),27(sudo)") is False


def test_docker_socket_mention_is_not_membership():
    # a path/socket reference to docker must NOT be read as group membership
    assert pe._user_in_docker_group("found /var/run/docker.sock and /etc/docker") is False


def test_empty_text_infeasible():
    assert pe._user_in_docker_group("") is False
    assert pe._user_in_docker_group(None) is False


# --- _extract_privesc_findings (classifier) ----------------------------------

def _findings_for(plan):
    state = {"critic_verdict": "PASS", "escalation_plan": plan,
             "escalation_result": "", "access_level": "user", "messages": [],
             "session_id": "3", "session_type": "command_shell"}
    return pe._extract_privesc_findings(state)


def test_classify_docker_plan_to_docker_group():
    plan = ("ESCALATION PLAN:\nTECHNIQUE: docker_group breakout\n"
            "STEPS:\n1. IMG=$(docker images -q | head -n1)\n"
            "2. docker run -v /:/mnt --rm $IMG chroot /mnt sh -c 'id; head -1 /etc/shadow'\n")
    assert _findings_for(plan)["technique"] == "docker_group"


def test_classify_docker_group_membership_phrasing():
    plan = "TECHNIQUE: abuse docker group membership via chroot the host filesystem"
    assert _findings_for(plan)["technique"] == "docker_group"


def test_classify_sudo_still_works():
    assert _findings_for("TECHNIQUE: sudo misconfiguration NOPASSWD")["technique"] == "sudo_miscfg"


def test_classify_suid_still_works():
    assert _findings_for("TECHNIQUE: SUID binary find shell escape")["technique"] == "suid"


def test_classify_kernel_still_works():
    assert _findings_for("TECHNIQUE: kernel exploit dirtycow")["technique"] == "kernel_exploit"


def test_docker_service_mention_not_misclassified_as_docker_group():
    # a sudo plan that merely names a docker service (no breakout signal) must
    # NOT be swallowed by the docker branch
    plan = "TECHNIQUE: sudo -l shows we can restart the docker daemon service"
    assert _findings_for(plan)["technique"] == "sudo_miscfg"


# --- _plan_mentions_docker (critic probe gate) -------------------------------

def test_plan_mentions_docker_true():
    assert pe._plan_mentions_docker("docker run -v /:/mnt --rm img chroot /mnt sh") is True
    assert pe._plan_mentions_docker("planted /tmp/rootbash via container") is True


def test_plan_mentions_docker_false_without_signal():
    assert pe._plan_mentions_docker("sudo -l abuse of find SUID") is False
    assert pe._plan_mentions_docker("the docker daemon is installed") is False
    assert pe._plan_mentions_docker("") is False


# --- prompt / catalog wiring -------------------------------------------------

def test_planner_prompt_carries_noninteractive_docker_vector():
    p = pe.PLANNER_PROMPT.lower()
    assert "docker" in p and "docker_group" in p
    assert "-it" in p  # explicitly warns against the interactive/hanging flag
    assert "chroot" in p


def test_enumerator_prompt_checks_docker_group():
    e = pe.ENUMERATOR_PROMPT.lower()
    assert "docker" in e and "group" in e


def test_critic_prompt_has_docker_rootbash_rule():
    c = pe.CRITIC_PROMPT.lower()
    assert "rootbash" in c and "euid=0" in c


def test_mitre_catalog_has_docker_group():
    t = mitre.get_technique("privilege_escalation", "docker_group")
    assert t is not None and t.slug == "docker_group"
    assert t.tactic == "privilege_escalation"
    # resolvable by id too
    assert mitre.get_technique("privilege_escalation", "T1611") is t


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    import warnings; warnings.filterwarnings("ignore")
    fails = 0
    for t in TESTS:
        try:
            t(); print(f"PASS {t.__name__}")
        except Exception as e:
            fails += 1; print(f"FAIL {t.__name__}: {e}")
    print(f"\n{len(TESTS)-fails}/{len(TESTS)} passed")
    sys.exit(1 if fails else 0)
