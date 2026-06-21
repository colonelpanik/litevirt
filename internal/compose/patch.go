package compose

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// PatchDiskStorage surgically sets vms.<vmKey>.disks.<diskName>.storage to pool
// in a compose YAML document, preserving the rest of the document (comments,
// ordering, other fields). It handles both disk shapes:
//   - shortform scalar (e.g. `data: 100G`) → expanded to `{size: 100G, storage: pool}`
//   - longform map (e.g. `data: {size: 100G,...}`) → sets/replaces the storage key
//
// If the disk isn't declared in the compose (e.g. an implicit root disk
// created from the image, with no `disks:` block), the disk entry is created
// as `{storage: pool}` so the move persists across a re-deploy. Only the VM
// def itself must already exist.
//
// Returns the new YAML, whether anything changed, and any error. If the VM
// isn't in the compose (or storage already equals pool), changed is false and
// err is nil — nothing to do.
//
// Used to keep a stack's stored compose YAML in sync after a disk pool move so
// `lv stack export` reflects the new placement and a re-deploy is idempotent.
func PatchDiskStorage(yamlStr, vmKey, diskName, pool string) (string, bool, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(yamlStr), &doc); err != nil {
		return yamlStr, false, fmt.Errorf("parse compose: %w", err)
	}
	if len(doc.Content) == 0 {
		return yamlStr, false, nil
	}
	root := doc.Content[0]
	disk := mapPath(root, "vms", vmKey, "disks", diskName)
	if disk == nil {
		// The disk isn't declared in the compose (e.g. an implicit root disk
		// created from the image). Create vms.<vmKey>.disks.<diskName>:
		// {storage: pool} so the pool move persists across `compose up`
		// instead of silently reverting. Requires the VM def to exist.
		vmDef := mapPath(root, "vms", vmKey)
		if vmDef == nil || vmDef.Kind != yaml.MappingNode {
			return yamlStr, false, nil
		}
		disks := mapValue(vmDef, "disks")
		if disks == nil {
			disks = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			vmDef.Content = append(vmDef.Content, scalarNode("disks"), disks)
		}
		if disks.Kind != yaml.MappingNode {
			return yamlStr, false, nil
		}
		disks.Content = append(disks.Content, scalarNode(diskName), &yaml.Node{
			Kind: yaml.MappingNode, Tag: "!!map",
			Content: []*yaml.Node{scalarNode("storage"), scalarNode(pool)},
		})
	} else {
		switch disk.Kind {
		case yaml.ScalarNode:
			// Shortform: the value is the size string. Expand into a map.
			size := disk.Value
			disk.Tag = "!!map"
			disk.Value = ""
			disk.Style = 0
			disk.Kind = yaml.MappingNode
			disk.Content = []*yaml.Node{
				scalarNode("size"), scalarNode(size),
				scalarNode("storage"), scalarNode(pool),
			}
		case yaml.MappingNode:
			if v := mapValue(disk, "storage"); v != nil {
				if v.Value == pool {
					return yamlStr, false, nil
				}
				v.Tag, v.Value, v.Style = "!!str", pool, 0
			} else {
				disk.Content = append(disk.Content, scalarNode("storage"), scalarNode(pool))
			}
		default:
			return yamlStr, false, nil
		}
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return yamlStr, false, fmt.Errorf("marshal compose: %w", err)
	}
	_ = enc.Close()
	return buf.String(), true, nil
}

// mapPath walks a chain of map keys from a mapping node, returning the value
// node at the end of the path, or nil if any segment is missing / not a map.
func mapPath(n *yaml.Node, keys ...string) *yaml.Node {
	cur := n
	for _, k := range keys {
		cur = mapValue(cur, k)
		if cur == nil {
			return nil
		}
	}
	return cur
}

// mapValue returns the value node for key in a mapping node, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalarNode(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
}
