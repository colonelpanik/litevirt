package pci

import (
	"encoding/csv"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// MIGInstance represents a GPU Multi-Instance GPU partition.
type MIGInstance struct {
	GPUIndex   int
	InstanceID int
	Profile    string // e.g. "1g.5gb", "3g.20gb"
	InUse      bool
}

// ListMIGInstances queries nvidia-smi for all MIG instances across all GPUs.
// nvidia-smi mig -lgi output columns: GPU, ID, Name, Placement,...
func ListMIGInstances() ([]MIGInstance, error) {
	out, err := exec.Command("nvidia-smi", "mig", "-lgi",
		"--format=csv,noheader,nounits").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nvidia-smi mig -lgi: %w: %s", err, out)
	}

	output := strings.TrimSpace(string(out))
	if output == "" {
		return nil, nil
	}

	r := csv.NewReader(strings.NewReader(output))
	r.TrimLeadingSpace = true
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse mig output: %w", err)
	}

	var instances []MIGInstance
	for _, rec := range records {
		if len(rec) < 3 {
			continue
		}
		gpuIdx, _ := strconv.Atoi(strings.TrimSpace(rec[0]))
		instID, _ := strconv.Atoi(strings.TrimSpace(rec[1]))
		profile := strings.TrimSpace(rec[2])

		instances = append(instances, MIGInstance{
			GPUIndex:   gpuIdx,
			InstanceID: instID,
			Profile:    profile,
		})
	}
	return instances, nil
}

// CreateMIGInstance creates a new MIG GPU Instance on the specified GPU
// and returns the instance with its assigned ID populated.
func CreateMIGInstance(gpuIndex int, profileName string) (*MIGInstance, error) {
	out, err := exec.Command("nvidia-smi", "mig",
		"-cgi", profileName,
		"-i", strconv.Itoa(gpuIndex)).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("create MIG instance: %w: %s", err, out)
	}

	// Parse the GI ID from the output (e.g. "Successfully created GPU instance ID  1...")
	giID := parseCreatedGIID(string(out))

	// Create the corresponding compute instance on the newly created GI.
	cciArgs := []string{"mig", "-cci", "-i", strconv.Itoa(gpuIndex)}
	if giID >= 0 {
		cciArgs = append(cciArgs, "-gi", strconv.Itoa(giID))
	}
	out, err = exec.Command("nvidia-smi", cciArgs...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("create MIG compute instance: %w: %s", err, out)
	}

	return &MIGInstance{
		GPUIndex:   gpuIndex,
		InstanceID: giID,
		Profile:    profileName,
	}, nil
}

// parseCreatedGIID extracts the GPU instance ID from nvidia-smi create output.
func parseCreatedGIID(output string) int {
	// Output typically: "Successfully created GPU instance ID  1 on GPU  0 using profile..."
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "GPU instance ID") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "ID" && i+1 < len(fields) {
					id, err := strconv.Atoi(fields[i+1])
					if err == nil {
						return id
					}
				}
			}
		}
	}
	return -1
}

// DestroyMIGInstance destroys a MIG GPU Instance.
func DestroyMIGInstance(gpuIndex, instanceID int) error {
	// Destroy compute instances first.
	exec.Command("nvidia-smi", "mig", "-dci",
		"-i", strconv.Itoa(gpuIndex),
		"-gi", strconv.Itoa(instanceID)).CombinedOutput()

	out, err := exec.Command("nvidia-smi", "mig", "-dgi",
		"-i", strconv.Itoa(gpuIndex),
		"-gi", strconv.Itoa(instanceID)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("destroy MIG instance: %w: %s", err, out)
	}
	return nil
}

// EnableMIG enables MIG mode on a GPU. Requires no active processes on the GPU.
func EnableMIG(gpuIndex int) error {
	out, err := exec.Command("nvidia-smi", "-i", strconv.Itoa(gpuIndex),
		"-mig", "1").CombinedOutput()
	if err != nil {
		return fmt.Errorf("enable MIG: %w: %s", err, out)
	}
	return nil
}

// DisableMIG disables MIG mode on a GPU. Requires all MIG instances to be destroyed first.
func DisableMIG(gpuIndex int) error {
	out, err := exec.Command("nvidia-smi", "-i", strconv.Itoa(gpuIndex),
		"-mig", "0").CombinedOutput()
	if err != nil {
		return fmt.Errorf("disable MIG: %w: %s", err, out)
	}
	return nil
}
