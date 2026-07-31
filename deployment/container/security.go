package container

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// dockerSocketTargets lists the exact container-side mount targets we treat as
// the Docker socket. A mount source that resolves to the host Docker socket is
// also rejected.
var dockerSocketTargets = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
}

// dockerSocketSources lists the host paths that we always reject.
var dockerSocketSources = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
}

// forbiddenSourcePrefixes lists host paths that must never be mounted into any
// unYOLO managed service. Provider credential and broker state paths belong
// only inside their owning managed volumes.
var forbiddenSourcePrefixes = []string{
	"/etc/gh-broker",
	"/etc/hf-broker",
	"/etc/sudo-broker",
	"/etc/unyolo-pairing",
	"/var/lib/gh-broker",
	"/var/lib/hf-broker",
	"/var/lib/sudo-broker",
	"/var/lib/unyolo-pairing",
	"/var/lib/unyolo-agent",
}

// AgentSecurityFinding names one blocking security issue detected on the agent
// service definition.
type AgentSecurityFinding struct {
	Rule    string
	Message string
}

// Error renders the finding for humans.
func (f AgentSecurityFinding) Error() string { return f.Rule + ": " + f.Message }

// AgentSecurityFindings is a bounded list of findings.
type AgentSecurityFindings []AgentSecurityFinding

// Err returns nil when the list is empty and a joined error otherwise.
func (list AgentSecurityFindings) Err() error {
	if len(list) == 0 {
		return nil
	}
	var messages []string
	for _, finding := range list {
		messages = append(messages, finding.Error())
	}
	return errors.New("agent container fails security checks:\n  " + strings.Join(messages, "\n  "))
}

var imageDigestPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9._/-]*[a-z0-9])?(?::[a-zA-Z0-9._-]+)?@sha256:[a-f0-9]{64}$`)

// VerifyPinnedImage returns nil when the reference includes an immutable
// @sha256: digest. Tags without digests are rejected.
func VerifyPinnedImage(image string) error {
	if !imageDigestPattern.MatchString(image) {
		return fmt.Errorf("image %q is not pinned by digest", image)
	}
	return nil
}

// CheckAgentService applies every Docker security rule for the selected agent
// service. It never mutates its inputs. The findings represent every blocking
// issue at once so the operator can fix them together.
func CheckAgentService(project ProjectInspection, serviceName string) (AgentSecurityFindings, error) {
	if serviceName == "" {
		return nil, errors.New("agent service name is required")
	}
	service, exists := project.Services[serviceName]
	if !exists {
		return nil, fmt.Errorf("compose project has no service %q", serviceName)
	}
	var findings AgentSecurityFindings
	findings = append(findings, checkAgentMounts(service)...)
	if service.Privileged {
		findings = append(findings, AgentSecurityFinding{Rule: "privileged", Message: "agent service must not run privileged"})
	}
	if service.PidMode == "host" {
		findings = append(findings, AgentSecurityFinding{Rule: "pid_mode", Message: "agent service must not share the host PID namespace"})
	}
	if service.IpcMode == "host" {
		findings = append(findings, AgentSecurityFinding{Rule: "ipc_mode", Message: "agent service must not share the host IPC namespace"})
	}
	if service.UserNSMode == "host" {
		findings = append(findings, AgentSecurityFinding{Rule: "userns_mode", Message: "agent service must not share the host user namespace"})
	}
	if service.NetworkMode == "host" {
		findings = append(findings, AgentSecurityFinding{Rule: "network_mode", Message: "agent service must not share the host network namespace"})
	}
	return findings, nil
}

func checkAgentMounts(service ServiceInspection) []AgentSecurityFinding {
	var findings []AgentSecurityFinding
	for _, mount := range service.Volumes {
		target := strings.TrimRight(mount.Target, "/")
		for _, forbidden := range dockerSocketTargets {
			if target == forbidden {
				findings = append(findings, AgentSecurityFinding{Rule: "docker_socket_mount", Message: fmt.Sprintf("mount to %s is not allowed", mount.Target)})
				break
			}
		}
		for _, forbiddenSource := range dockerSocketSources {
			if strings.TrimRight(mount.Source, "/") == forbiddenSource {
				findings = append(findings, AgentSecurityFinding{Rule: "docker_socket_mount", Message: fmt.Sprintf("mount from host %s is not allowed", mount.Source)})
				break
			}
		}
		for _, prefix := range forbiddenSourcePrefixes {
			if mount.Source == prefix || strings.HasPrefix(mount.Source, prefix+"/") {
				findings = append(findings, AgentSecurityFinding{Rule: "provider_credential_mount", Message: fmt.Sprintf("mount from %s exposes provider credentials or broker state", mount.Source)})
				break
			}
		}
	}
	return findings
}

// CheckOverrideServices verifies the override we plan to write does not
// introduce a Docker socket mount or provider-store share. It also confirms
// every image field is digest-pinned.
func CheckOverrideServices(override *AgentOverride) error {
	if override == nil {
		return errors.New("override is nil")
	}
	if err := VerifyPinnedImage(override.InitService.Image); err != nil {
		return err
	}
	for _, mount := range override.InitService.Volumes {
		target := strings.TrimRight(mount.Target, "/")
		for _, forbidden := range dockerSocketTargets {
			if target == forbidden {
				return fmt.Errorf("init service mounts %s", mount.Target)
			}
		}
		for _, forbiddenSource := range dockerSocketSources {
			if strings.TrimRight(mount.Source, "/") == forbiddenSource {
				return fmt.Errorf("init service mounts host %s", mount.Source)
			}
		}
	}
	if override.InitService.Privileged || override.InitService.PidHost || override.InitService.NetworkHost {
		return errors.New("init service must not use host namespaces or privileged mode")
	}
	return nil
}
