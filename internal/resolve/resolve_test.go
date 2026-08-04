package resolve

import "testing"

func TestParseResourceArg(t *testing.T) {
	cases := []struct {
		in       string
		wantKind string
		wantName string
		wantErr  bool
	}{
		{"pod/my-pod", "pod", "my-pod", false},
		{"po/my-pod", "pod", "my-pod", false},
		{"deploy/my-app", "deployment", "my-app", false},
		{"deployment/my-app", "deployment", "my-app", false},
		{"cronjob/my-job", "cronjob", "my-job", false},
		{"my-pod", "", "", true},
		{"pod/", "", "", true},
		{"", "", "", true},
	}
	for _, c := range cases {
		kind, name, err := ParseResourceArg(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseResourceArg(%q): expected error, got none", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseResourceArg(%q): unexpected error: %v", c.in, err)
			continue
		}
		if kind != c.wantKind || name != c.wantName {
			t.Errorf("ParseResourceArg(%q) = (%q, %q), want (%q, %q)", c.in, kind, name, c.wantKind, c.wantName)
		}
	}
}

func TestDigestRefFromImageID(t *testing.T) {
	cases := []struct {
		name    string
		imageID string
		image   string
		want    string
	}{
		{
			name:    "already digest reference",
			imageID: "docker-pullable://ghcr.io/example/app@sha256:aaaa",
			image:   "ghcr.io/example/app:1.0.0",
			want:    "ghcr.io/example/app@sha256:aaaa",
		},
		{
			name:    "bare digest, tag-based image",
			imageID: "sha256:bbbb",
			image:   "ghcr.io/example/app:1.0.0",
			want:    "ghcr.io/example/app@sha256:bbbb",
		},
		{
			name:    "bare digest, image with port and no tag",
			imageID: "sha256:cccc",
			image:   "localhost:5000/example/app",
			want:    "localhost:5000/example/app@sha256:cccc",
		},
		{
			name:    "unresolvable image id",
			imageID: "",
			image:   "ghcr.io/example/app:1.0.0",
			want:    "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := digestRefFromImageID(c.imageID, c.image)
			if got != c.want {
				t.Errorf("digestRefFromImageID(%q, %q) = %q, want %q", c.imageID, c.image, got, c.want)
			}
		})
	}
}
