# Container images (Podman / Docker)
.PHONY: container
container: tayga-clat.tar tayga-nat64.tar tayga.tar

PODMAN_FLAGS := --cgroup-manager=cgroupfs
ifdef CONT_ALL
PODMAN_FLAGS += --all-platforms
endif

tayga.tar: container/Containerfile
	$(RM) $@
	podman manifest create tayga
	podman build $(PODMAN_FLAGS) -f container/Containerfile . --manifest tayga --target production
ifdef CONT_PUSH
	podman manifest push --all tayga ghcr.io/antongrizli/tayga:latest
endif
	podman save -o $@ tayga
	podman manifest rm tayga 2>/dev/null || true

tayga-clat.tar: container/Containerfile
	$(RM) $@
	podman manifest create tayga-clat
	podman build $(PODMAN_FLAGS) -f container/Containerfile . --manifest tayga-clat --target clat
ifdef CONT_PUSH
	podman manifest push --all tayga-clat ghcr.io/antongrizli/tayga-clat:latest
endif
	podman save -o $@ tayga-clat
	podman manifest rm tayga-clat 2>/dev/null || true

tayga-nat64.tar: container/Containerfile
	$(RM) $@
	podman manifest create tayga-nat64
	podman build $(PODMAN_FLAGS) -f container/Containerfile . --manifest tayga-nat64 --target nat64
ifdef CONT_PUSH
	podman manifest push --all tayga-nat64 ghcr.io/antongrizli/tayga-nat64:latest
endif
	podman save -o $@ tayga-nat64
	podman manifest rm tayga-nat64 2>/dev/null || true
