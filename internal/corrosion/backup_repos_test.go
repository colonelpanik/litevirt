package corrosion

import (
	"context"
	"testing"
)

func TestBackupRepoCRUD(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	if err := UpsertBackupRepo(ctx, c, BackupRepo{Name: "main", Path: "/srv/backup/main", StackName: "s1"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	p, err := GetBackupRepoPath(ctx, c, "main")
	if err != nil || p != "/srv/backup/main" {
		t.Fatalf("get = %q, %v; want /srv/backup/main", p, err)
	}
	// Upsert again with a new path — must not duplicate.
	if err := UpsertBackupRepo(ctx, c, BackupRepo{Name: "main", Path: "/srv/backup/main2", StackName: "s1"}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	repos, _ := ListBackupRepos(ctx, c)
	if len(repos) != 1 || repos[0].Path != "/srv/backup/main2" {
		t.Fatalf("repos = %+v, want one updated entry", repos)
	}
	// Unknown name resolves to "".
	if p, _ := GetBackupRepoPath(ctx, c, "nope"); p != "" {
		t.Fatalf("unknown repo resolved to %q, want empty", p)
	}
	// Stack teardown removes it.
	if err := DeleteStackBackupRepos(ctx, c, "s1"); err != nil {
		t.Fatalf("delete stack repos: %v", err)
	}
	if repos, _ := ListBackupRepos(ctx, c); len(repos) != 0 {
		t.Fatalf("after teardown = %+v, want empty", repos)
	}
}
