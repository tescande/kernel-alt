%global package_speccommit 5588078146d0777e58d4a03cda9ac75977a12d90
%global usver 4.19.19
%global package_srccommit refs/tags/v4.19.311
%define uname 4.19.311
%define short_uname 4.19
%define srcpath /usr/src/kernels/%{uname}-%{_arch}

# Control whether we perform a compat. check against published ABI.
# Default enabled: (to override: --without kabichk)
#%define do_kabichk  %{?_without_kabichk: 0} %{?!_without_kabichk: 1}
# Default disabled: (to override: --with kabichk)
%define do_kabichk  %{?_with_kabichk: 1} %{?!_with_kabichk: 0}

#
# Adjust debuginfo generation to suit building a kernel:
#
# Don't run dwz.
%undefine _find_debuginfo_dwz_opts
# Don't try to generate minidebuginfo.
%undefine _include_minidebuginfo
# Resolve trivial relocations in debug sections.
# This reduces the size of debuginfo.
%define _find_debuginfo_opts -r

# RPM tries to bytecompile Python sources files it finds in /usr/src and fails
# since some of them are for Python 3 only. Just ignore the errors.
%global _python_bytecompile_errors_terminate_build 0

%define lp_devel_dir %{_usrsrc}/kernel-%{version}-%{release}

# Prevent RPM adding Provides/Requires to lp-devel package
%global __provides_exclude_from ^%{lp_devel_dir}/.*$
%global __requires_exclude_from ^%{lp_devel_dir}/.*$

Name: kernel-alt
License: GPLv2
Version: %{uname}
Release: %{?xsrel}1%{?dist}
ExclusiveArch: x86_64
ExclusiveOS: Linux
Summary: The Linux kernel
BuildRequires: kmod

# These build dependencies are needed for building the main kernel and
# modules as well live patches.
%define core_builddeps() %{lua:
    deps = {
        'bc',
        'bison',
        'gcc',
        'elfutils-libelf-devel',
        'elfutils-devel',
        'binutils-devel',
        'flex',
        'hostname',
        'openssl-devel'
    }
    for _, dep in ipairs(deps) do
        print(rpm.expand("%1") .. ': ' .. dep .. '\\n')
    end
}

%{core_builddeps BuildRequires}
%if %{do_kabichk}
BuildRequires: python
%endif

BuildRequires: xz-devel
BuildRequires: libunwind-devel
BuildRequires: python2-devel
BuildRequires: asciidoc xmlto
%{?_cov_buildrequires}
AutoReqProv: no
# Don't provide kernel Provides: we don't want kernel-alt to be pulled instead of main kernel
#Provides: kernel-uname-r = %{uname}
#Provides: kernel = %{version}-%{release}
#Provides: kernel-%{_arch} = %{version}-%{release}
Requires(post): coreutils kmod
# xcp-python-libs required for handling grub configuration
Requires(post): xcp-python-libs >= 3.0.2-4.2.xcpng8.3
Requires(postun): xcp-python-libs >= 3.0.2-4.2.xcpng8.3
Requires(posttrans): xcp-python-libs >= 3.0.2-4.2.xcpng8.3
Requires(posttrans): coreutils dracut kmod

Source0: kernel-alt-4.19.311.tar.gz
Source1: SOURCES/kernel/kernel-x86_64.config
Source2: SOURCES/kernel/macros.kernel
Source3: SOURCES/kernel/check-kabi
Source4: SOURCES/kernel/Module.kabi

Patch001: 0001-mtip32xx-fully-switch-to-the-generic-DMA-API.patch
Patch002: 0002-mtip32xx-clean-an-indentation-issue-remove-extraneou.patch
Patch003: 0001-scsi-libfc-retry-PRLI-if-we-cannot-analyse-the-paylo.patch
Patch004: 0003-mtip32xx-move-the-blk_rq_map_sg-call-to-mtip_hw_subm.patch
Patch005: 0004-mtip32xx-merge-mtip_submit_request-into-mtip_queue_r.patch
Patch006: 0005-mtip32xx-return-a-blk_status_t-from-mtip_send_trim.patch
Patch007: 0006-mtip32xx-remove-__force_bit2int.patch
Patch008: 0007-mtip32xx-add-missing-endianess-annotations-on-struct.patch
Patch009: 0008-mtip32xx-remove-mtip_init_cmd_header.patch
Patch010: 0009-mtip32xx-remove-mtip_get_int_command.patch
Patch011: 0010-mtip32xx-don-t-use-req-special.patch
Patch012: 0011-mtip32xxx-use-for_each_sg.patch
Patch013: 0012-mtip32xx-avoid-using-semaphores.patch
Patch014: 0013-mtip32xx-use-BLK_STS_DEV_RESOURCE-for-device-resourc.patch
Patch015: 0001-dlm-don-t-allow-zero-length-names.patch
Patch016: 0001-dlm-NULL-check-before-some-freeing-functions-is-not-.patch
Patch017: 0001-ACPI-APEI-Fix-possible-out-of-bounds-access-to-BERT-.patch
Patch018: 0001-gfs-no-need-to-check-return-value-of-debugfs_create-.patch
Patch019: 0001-iomap-Clean-up-__generic_write_end-calling.patch
Patch020: 0002-fs-Turn-__generic_write_end-into-a-void-function.patch
Patch021: 0003-iomap-Fix-use-after-free-error-in-page_done-callback.patch
Patch022: 0004-iomap-Add-a-page_prepare-callback.patch
Patch023: 0001-fs-mark-expected-switch-fall-throughs.patch
Patch024: 0009-SUNRPC-Ensure-that-the-transport-layer-respect-major.patch
Patch025: 0011-SUNRPC-Start-the-first-major-timeout-calculation-at-.patch
Patch026: 0001-iomap-don-t-mark-the-inode-dirty-in-iomap_write_end.patch
Patch027: 0001-dlm-no-need-to-check-return-value-of-debugfs_create-.patch
Patch028: 0001-kernel-module.c-Only-return-EEXIST-for-modules-that-.patch
Patch029: 0001-drm-i915-gvt-Allow-F_CMD_ACCESS-on-mmio-0x21f0.patch
Patch030: 0001-xen-events-remove-event-handling-recursion-detection.patch
Patch031: 0001-drm-i915-gvt-fix-high-order-allocation-failure-on-la.patch
Patch032: 0001-drm-i915-gvt-Add-mutual-lock-for-ppgtt-mm-LRU-list.patch
Patch033: 0002-drm-i915-gvt-more-locking-for-ppgtt-mm-LRU-list.patch
Patch034: 0001-dlm-Switch-to-using-wait_event.patch
Patch035: 0001-dlm-use-the-tcp-version-of-accept_from_sock-for-sctp.patch
Patch036: 0002-net-add-sock_set_reuseaddr.patch
Patch037: 0003-net-add-sock_set_sndtimeo.patch
Patch038: 0004-net-add-sock_set_keepalive.patch
Patch039: 0005-net-add-sock_set_rcvbuf.patch
Patch040: 0006-tcp-add-tcp_sock_set_nodelay.patch
Patch041: 0007-sctp-add-sctp_sock_set_nodelay.patch
Patch042: 0009-dlm-dlm_internal-Replace-zero-length-array-with-flex.patch
Patch043: 0010-dlm-user-Replace-zero-length-array-with-flexible-arr.patch
Patch044: 0011-fs-dlm-remove-unneeded-semicolon-in-rcom.c.patch
Patch045: 0001-scsi-libfc-free-response-frame-from-GPN_ID.patch
Patch046: 0001-net-sock-add-sock_set_mark.patch
Patch047: 0015-fs-dlm-set-skb-mark-for-listen-socket.patch
Patch048: 0016-fs-dlm-set-skb-mark-per-peer-socket.patch
Patch049: 0017-fs-dlm-don-t-close-socket-on-invalid-message.patch
Patch050: 0018-fs-dlm-change-handling-of-reconnects.patch
Patch051: 0019-fs-dlm-implement-tcp-graceful-shutdown.patch
Patch052: 0021-fs-dlm-synchronize-dlm-before-shutdown.patch
Patch053: 0022-fs-dlm-make-connection-hash-lockless.patch
Patch054: 0023-fs-dlm-fix-dlm_local_addr-memory-leak.patch
Patch055: 0025-fs-dlm-move-free-writequeue-into-con-free.patch
Patch056: 0026-fs-dlm-handle-possible-othercon-writequeues.patch
Patch057: 0027-fs-dlm-use-free_con-to-free-connection.patch
Patch058: 0028-fs-dlm-remove-lock-dependency-warning.patch
Patch059: 0029-fs-dlm-fix-mark-per-nodeid-setting.patch
Patch060: 0030-fs-dlm-handle-range-check-as-callback.patch
Patch061: 0031-fs-dlm-disallow-buffer-size-below-default.patch
Patch062: 0032-fs-dlm-rework-receive-handling.patch
Patch063: 0033-fs-dlm-fix-race-in-nodeid2con.patch
Patch064: 0034-fs-dlm-fix-proper-srcu-api-call.patch
Patch065: 0035-fs-dlm-define-max-send-buffer.patch
Patch066: 0036-fs-dlm-add-get-buffer-error-handling.patch
Patch067: 0037-fs-dlm-flush-othercon-at-close.patch
Patch068: 0038-fs-dlm-handle-non-blocked-connect-event.patch
Patch069: 0039-fs-dlm-add-helper-for-init-connection.patch
Patch070: 0040-fs-dlm-move-connect-callback-in-node-creation.patch
Patch071: 0041-fs-dlm-move-shutdown-action-to-node-creation.patch
Patch072: 0042-fs-dlm-refactor-sctp-sock-parameter.patch
Patch073: 0043-fs-dlm-listen-socket-out-of-connection-hash.patch
Patch074: 0044-fs-dlm-fix-check-for-multi-homed-hosts.patch
Patch075: 0045-fs-dlm-constify-addr_compare.patch
Patch076: 0046-fs-dlm-check-on-existing-node-address.patch
Patch077: 0001-xen-netback-avoid-race-in-xenvif_rx_ring_slots_avail.patch
Patch078: 0007-xen-evtchn-use-smp-barriers-for-user-event-ring.patch
Patch079: 0008-xen-evtchn-use-READ-WRITE_ONCE-for-accessing-ring-in.patch
Patch080: 0001-x86-ioperm-Add-new-paravirt-function-update_io_bitma.patch
Patch081: 0047-fs-dlm-fix-debugfs-dump.patch
Patch082: 0048-fs-dlm-fix-mark-setting-deadlock.patch
Patch083: 0049-fs-dlm-set-connected-bit-after-accept.patch
Patch084: 0050-fs-dlm-set-subclass-for-othercon-sock_mutex.patch
Patch085: 0051-fs-dlm-add-errno-handling-to-check-callback.patch
Patch086: 0052-fs-dlm-add-check-if-dlm-is-currently-running.patch
Patch087: 0053-fs-dlm-change-allocation-limits.patch
Patch088: 0054-fs-dlm-use-GFP_ZERO-for-page-buffer.patch
Patch089: 0055-fs-dlm-simplify-writequeue-handling.patch
Patch090: 0056-fs-dlm-check-on-minimum-msglen-size.patch
Patch091: 0057-fs-dlm-remove-unaligned-memory-access-handling.patch
Patch092: 0058-fs-dlm-flush-swork-on-shutdown.patch
Patch093: 0059-fs-dlm-add-shutdown-hook.patch
Patch094: 0060-fs-dlm-fix-missing-unlock-on-error-in-accept_from_so.patch
Patch095: 0061-fs-dlm-always-run-complete-for-possible-waiters.patch
Patch096: 0062-fs-dlm-add-dlm-macros-for-ratelimit-log.patch
Patch097: 0063-fs-dlm-fix-srcu-read-lock-usage.patch
Patch098: 0064-fs-dlm-set-is-othercon-flag.patch
Patch099: 0065-fs-dlm-reconnect-if-socket-error-report-occurs.patch
Patch100: 0067-fs-dlm-fix-connection-tcp-EOF-handling.patch
Patch101: 0068-fs-dlm-public-header-in-out-utility.patch
Patch102: 0069-fs-dlm-add-more-midcomms-hooks.patch
Patch103: 0070-fs-dlm-make-buffer-handling-per-msg.patch
Patch104: 0071-fs-dlm-add-functionality-to-re-transmit-a-message.patch
Patch105: 0072-fs-dlm-move-out-some-hash-functionality.patch
Patch106: 0073-fs-dlm-add-union-in-dlm-header-for-lockspace-id.patch
Patch107: 0074-fs-dlm-add-reliable-connection-if-reconnect.patch
Patch108: 0075-fs-dlm-add-midcomms-debugfs-functionality.patch
Patch109: 0076-fs-dlm-don-t-allow-half-transmitted-messages.patch
Patch110: 0077-fs-dlm-Fix-memory-leak-of-object-mh.patch
Patch111: 0078-fs-dlm-Fix-spelling-mistake-stucked-stuck.patch
Patch112: 0079-fs-dlm-fix-lowcomms_start-error-case.patch
Patch113: 0081-fs-dlm-use-alloc_ordered_workqueue.patch
Patch114: 0082-fs-dlm-move-dlm-allow-conn.patch
Patch115: 0083-fs-dlm-introduce-proto-values.patch
Patch116: 0084-fs-dlm-rename-socket-and-app-buffer-defines.patch
Patch117: 0085-fs-dlm-fix-race-in-mhandle-deletion.patch
Patch118: 0086-fs-dlm-invalid-buffer-access-in-lookup-error.patch
Patch119: 0087-fs-dlm-use-sk-sk_socket-instead-of-con-sock.patch
Patch120: 0088-fs-dlm-use-READ_ONCE-for-config-var.patch
Patch121: 0089-fs-dlm-fix-typo-in-tlv-prefix.patch
Patch122: 0090-fs-dlm-clear-CF_APP_LIMITED-on-close.patch
Patch123: 0091-fs-dlm-cleanup-and-remove-_send_rcom.patch
Patch124: 0092-fs-dlm-introduce-con_next_wq-helper.patch
Patch125: 0093-fs-dlm-move-to-static-proto-ops.patch
Patch126: 0094-fs-dlm-introduce-generic-listen.patch
Patch127: 0095-fs-dlm-auto-load-sctp-module.patch
Patch128: 0096-fs-dlm-generic-connect-func.patch
Patch129: 0097-fs-dlm-fix-multiple-empty-writequeue-alloc.patch
Patch130: 0098-fs-dlm-move-receive-loop-into-receive-handler.patch
Patch131: 0099-fs-dlm-implement-delayed-ack-handling.patch
Patch132: 0100-fs-dlm-fix-return-EINTR-on-recovery-stopped.patch
Patch133: 0101-fs-dlm-avoid-comms-shutdown-delay-in-release_lockspa.patch
Patch134: 0001-x86-timer-Skip-PIT-initialization-on-modern-chipsets.patch
Patch135: 0001-x86-timer-Force-PIT-initialization-when-X86_FEATURE_.patch
Patch136: 0001-x86-timer-Don-t-skip-PIT-setup-when-APIC-is-disabled.patch
Patch137: 0001-nbd-Fix-use-after-free-in-pid_show.patch
Patch138: 0001-fs-dlm-remove-check-SCTP-is-loaded-message.patch
Patch139: 0001-fs-dlm-let-handle-callback-data-as-void.patch
Patch140: 0001-fs-dlm-remove-double-list_first_entry-call.patch
Patch141: 0001-fs-dlm-don-t-call-kernel_getpeername-in-error_report.patch
Patch142: 0001-fs-dlm-replace-use-of-socket-sk_callback_lock-with-s.patch
Patch143: 0001-fs-dlm-fix-build-with-CONFIG_IPV6-disabled.patch
Patch144: 0001-fs-dlm-check-for-pending-users-filling-buffers.patch
Patch145: 0001-fs-dlm-remove-wq_alloc-mutex.patch
Patch146: 0001-fs-dlm-memory-cache-for-writequeue_entry.patch
Patch147: 0001-fs-dlm-memory-cache-for-lowcomms-hotpath.patch
Patch148: 0001-fs-dlm-print-cluster-addr-if-non-cluster-node-connec.patch
Patch149: 0001-xen-x86-obtain-upper-32-bits-of-video-frame-buffer-a.patch
Patch150: 0001-xen-x86-obtain-full-video-frame-buffer-address-for-D.patch
Patch151: 0001-dlm-uninitialized-variable-on-error-in-dlm_listen_fo.patch
Patch152: 0001-dlm-add-__CHECKER__-for-false-positives.patch
Patch153: 0001-fs-dlm-fix-grammar-in-lowcomms-output.patch
Patch154: 0001-fs-dlm-fix-race-in-lowcomms.patch
Patch155: 0001-fs-dlm-relax-sending-to-allow-receiving.patch
Patch156: 0001-fs-dlm-fix-sock-release-if-listen-fails.patch
Patch157: 0002-fs-dlm-retry-accept-until-EAGAIN-or-error-returns.patch
Patch158: 0003-fs-dlm-remove-send-repeat-remove-handling.patch
Patch159: 0001-nvme_fc-add-nvme_discovery-sysfs-attribute-to-fc-tra.patch
Patch160: 0001-ACPI-processor-Fix-evaluating-_PDC-method-when-runni.patch
Patch161: 0001-nvme-fabrics-reject-I-O-to-offline-device.patch
Patch162: 0002-xen-netback-remove-unused-variables-pending_idx-and-.patch
Patch163: 0004-xen-netback-remove-not-needed-test-in-xenvif_tx_buil.patch
Patch164: kbuild-AFTER_LINK.patch
Patch165: expose-xsversion.patch
Patch166: blktap2.patch
Patch167: blkback-kthread-pid.patch
Patch168: tg3-alloc-repeat.patch
Patch169: disable-EFI-Properties-table-for-Xen.patch
Patch170: net-Do-not-scrub-ignore_df-within-the-same-name-spac.patch
Patch171: enable-fragmention-gre-packets.patch
Patch172: CA-285778-emulex-nic-ip-hdr-len.patch
Patch173: cifs-Change-the-default-value-SecFlags-to-0x83.patch
Patch174: call-kexec-before-offlining-noncrashing-cpus.patch
Patch175: hide-hung-task-for-idle-class.patch
Patch176: xfs-async-wait.patch
Patch177: 0001-dma-add-dma_get_required_mask_from_max_pfn.patch
Patch178: 0002-x86-xen-correct-dma_get_required_mask-for-Xen-PV-gue.patch
Patch179: map-1MiB-1-1.patch
Patch180: hide-nr_cpus-warning.patch
Patch181: disable-pm-timer.patch
Patch182: increase-nr-irqs.patch
Patch183: xen-balloon-hotplug-select-HOLES_IN_ZONE.patch
Patch184: 0001-pci-export-pci_probe_reset_function.patch
Patch185: 0002-xen-pciback-provide-a-reset-sysfs-file-to-try-harder.patch
Patch186: pciback-disable-root-port-aer.patch
Patch187: pciback-mask-root-port-comp-timeout.patch
Patch188: no-flr-quirk.patch
Patch189: revert-PCI-Probe-for-device-reset-support-during-enumeration.patch
Patch190: CA-135938-nfs-disconnect-on-rpc-retry.patch
Patch191: sunrpc-force-disconnect-on-connection-timeout.patch
Patch192: nfs-avoid-double-timeout.patch
Patch193: bonding-balance-slb.patch
Patch194: bridge-lock-fdb-after-garp.patch
Patch195: CP-13181-net-openvswitch-add-dropping-of-fip-and-lldp.patch
Patch196: xen-ioemu-inject-msi.patch
Patch197: pv-iommu-support.patch
Patch198: kexec-reserve-crashkernel-region.patch
Patch199: 0001-xen-swiotlb-rework-early-repeat-code.patch
Patch200: 0001-arch-x86-xen-add-infrastruction-in-xen-to-support-gv.patch
Patch201: 0002-drm-i915-gvt-write-guest-ppgtt-entry-for-xengt-suppo.patch
Patch202: 0003-drm-i915-xengt-xengt-moudule-initial-files.patch
Patch203: 0004-drm-i915-xengt-check-on_destroy-on-pfn_to_mfn.patch
Patch204: 0005-arch-x86-xen-Import-x4.9-interface-for-ioreq.patch
Patch205: 0006-i915-gvt-xengt.c-Use-new-dm_op-instead-of-hvm_op.patch
Patch206: 0007-i915-gvt-xengt.c-New-interface-to-write-protect-PPGT.patch
Patch207: 0008-i915-gvt-xengt.c-Select-vgpu-type-according-to-low_g.patch
Patch208: 0009-drm-i915-gvt-Don-t-output-error-message-when-DomU-ma.patch
Patch209: 0010-drm-i915-gvt-xengt-Correctly-get-low-mem-max-gfn.patch
Patch210: 0011-drm-i915-gvt-Fix-dom0-call-trace-at-shutdown-or-rebo.patch
Patch211: 0012-hvm-dm_op.h-Sync-dm_op-interface-to-xen-4.9-release.patch
Patch212: 0013-drm-i915-gvt-Apply-g2h-adjust-for-GTT-mmio-access.patch
Patch213: 0014-drm-i915-gvt-Apply-g2h-adjustment-during-fence-mmio-.patch
Patch214: 0015-drm-i915-gvt-Patch-the-gma-in-gpu-commands-during-co.patch
Patch215: 0016-drm-i915-gvt-Retrieve-the-guest-gm-base-address-from.patch
Patch216: 0017-drm-i915-gvt-Align-the-guest-gm-aperture-start-offse.patch
Patch217: 0018-drm-i915-gvt-Add-support-to-new-VFIO-subregion-VFIO_.patch
Patch218: 0019-drm-i915-gvt-Implement-vGPU-status-save-and-restore-.patch
Patch219: 0020-vfio-Implement-new-Ioctl-VFIO_IOMMU_GET_DIRTY_BITMAP.patch
Patch220: 0021-drm-i915-gvt-Add-dev-node-for-vGPU-state-save-restor.patch
Patch221: 0022-drm-i915-gvt-Add-interface-to-control-the-vGPU-runni.patch
Patch222: 0023-drm-i915-gvt-Modify-the-vGPU-save-restore-logic-for-.patch
Patch223: 0024-drm-i915-gvt-Add-log-dirty-support-for-XENGT-migrati.patch
Patch224: 0025-drm-i915-gvt-xengt-Add-iosrv_enabled-to-track-iosrv-.patch
Patch225: 0026-drm-i915-gvt-Add-xengt-ppgtt-write-handler.patch
Patch226: 0027-drm-i915-gvt-xengt-Impliment-mpt-dma_map-unmap_guest.patch
Patch227: 0028-drm-i915-gvt-introduce-a-new-VFIO-region-for-vfio-de.patch
Patch228: 0029-drm-i915-gvt-change-the-return-value-of-opregion-acc.patch
Patch229: 0030-drm-i915-gvt-Rebase-the-code-to-gvt-staging-for-live.patch
Patch230: 0031-drm-i915-gvt-Apply-g2h-adjustment-to-buffer-start-gm.patch
Patch231: 0032-drm-i915-gvt-Fix-xengt-opregion-handling-in-migratio.patch
Patch232: 0033-drm-i915-gvt-XenGT-migration-optimize.patch
Patch233: 0034-drm-i915-gvt-Add-vgpu-execlist-info-into-migration-d.patch
Patch234: 0035-drm-i915-gvt-Emulate-ring-mode-register-restore-for-.patch
Patch235: 0036-drm-i915-gvt-Use-copy_to_user-to-return-opregion.patch
Patch236: 0037-drm-i915-gvt-Expose-opregion-in-vgpu-open.patch
Patch237: 0038-drm-i915-gvt-xengt-Don-t-shutdown-vm-at-ioreq-failur.patch
Patch238: 0039-drm-i915-gvt-Emulate-hw-status-page-address-register.patch
Patch239: 0040-drm-i915-gvt-migration-copy-vregs-on-vreg-load.patch
Patch240: 0041-drm-i915-gvt-Fix-a-command-corruption-caused-by-live.patch
Patch241: 0042-drm-i915-gvt-update-force-to-nonpriv-register-whitel.patch
Patch242: 0043-drm-i915-gvt-xengt-Fix-xengt-instance-destroy-error.patch
Patch243: 0044-drm-i915-gvt-invalidate-old-ggtt-page-when-update-gg.patch
Patch244: 0045-drm-i915-gvt-support-inconsecutive-partial-gtt-entry.patch
Patch245: set-XENMEM_get_mfn_from_pfn-hypercall-number.patch
Patch246: gvt-enforce-primary-class-id.patch
Patch247: gvt-use-xs-vgpu-type.patch
Patch248: xengt-pviommu-basic.patch
Patch249: xengt-pviommu-unmap.patch
Patch250: get_domctl_interface_version.patch
Patch251: xengt-fix-shutdown-failures.patch
Patch252: xengt-i915-gem-vgtbuffer.patch
Patch253: xengt-gtt-2m-alignment.patch
Patch254: net-core__order-3_frag_allocator_causes_swiotlb_bouncing_under_xen.patch
Patch255: idle_cpu-return-0-during-softirq.patch
Patch256: default-xen-swiotlb-size-128MiB.patch
Patch257: dlm__increase_socket_backlog_to_avoid_hangs_with_16_nodes.patch
Patch258: 0001-Add-auxiliary-bus-support.patch
Patch259: 0002-driver-core-auxiliary-bus-move-slab.h-from-include-f.patch
Patch260: 0003-driver-core-auxiliary-bus-make-remove-function-retur.patch
Patch261: 0004-driver-core-auxiliary-bus-minor-coding-style-tweaks.patch
Patch262: 0005-driver-core-auxiliary-bus-Fix-auxiliary-bus-shutdown.patch
Patch263: 0006-driver-core-auxiliary-bus-Fix-calling-stage-for-auxi.patch
Patch264: 0007-driver-core-auxiliary-bus-Remove-unneeded-module-bit.patch
Patch265: 0008-driver-core-auxiliary-bus-Fix-memory-leak-when-drive.patch
Patch266: 0009-Documentation-auxiliary_bus-Clarify-auxiliary_device.patch
Patch267: 0010-Documentation-auxiliary_bus-Clarify-__auxiliary_driv.patch
Patch268: 0011-Documentation-auxiliary_bus-Clarify-the-release-of-d.patch
Patch269: 0012-Documentation-auxiliary_bus-Move-the-text-into-the-c.patch
Patch270: 0013-CP-41018-Make-CONFIG_AUXILIARY_BUS-y-work.patch

Provides: gitsha(ssh://git@code.citrite.net/XSU/linux-stable.git) = dffbba4348e9686d6bf42d54eb0f2cd1c4fb3520
Provides: gitsha(ssh://git@code.citrite.net/XS/linux.pg.git) = cb3c28f7e8213ef44e5c06369b577a18b86af291

%if %{do_kabichk}
%endif

%description
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system. The kernel handles the basic functions of the operating
system: memory allocation, process allocation, device input and output, etc.


%package headers
License: GPLv2
Summary: Header files for the Linux kernel for use by glibc
Group: Development/System
# Don't provide kernel Provides: we don't want kernel-alt to be pulled instead of main kernel
#Obsoletes: glibc-kernheaders < 3.0-46
#Provides: glibc-kernheaders = 3.0-46
#Provides: kernel-headers = %{uname}
Conflicts: kernel-headers < %{uname}

%description headers
Kernel-headers includes the C header files that specify the interface
between the Linux kernel and userspace libraries and programs.  The
header files define structures and constants that are needed for
building most standard programs and are also needed for rebuilding the
glibc package.

%package devel
License: GPLv2
Summary: Development package for building kernel modules to match the %{uname} kernel
Group: System Environment/Kernel
AutoReqProv: no
# Don't provide kernel Provides: we don't want kernel-alt to be pulled instead of main kernel
#Provides: kernel-devel-%{_arch} = %{version}-%{release}
#Provides: kernel-devel-uname-r = %{uname}
Requires: elfutils-libelf-devel

%description devel
This package provides kernel headers and makefiles sufficient to build modules
against the %{uname} kernel.

#%package lp-devel_%{version}_%{release}
#License: GPLv2
#Summary: Development package for building livepatches
#Group: Development/System
#%{core_builddeps Requires}

#%description lp-devel_%{version}_%{release}
#Contains the prepared source files, config, and vmlinux for building live
#patches against base version %{version}-%{release}.

%package -n perf-alt
Summary: Performance monitoring for the Linux kernel
License: GPLv2
Conflicts: perf
%description -n perf-alt
This package contains the perf tool, which enables performance monitoring
of the Linux kernel.

%global pythonperfsum Python bindings for apps which will manipulate perf events
%global pythonperfdesc A Python module that permits applications \
written in the Python programming language to use the interface \
to manipulate perf events.

%package -n python2-perf-alt
Summary: %{pythonperfsum}
Provides: python2-perf-alt
Conflicts: python2-perf
%description -n python2-perf-alt
%{pythonperfdesc}

%prep
%autosetup -p1
%{?_cov_prepare}

%build
#source %{SOURCE5}

# This override tweaks the kernel makefiles so that we run debugedit on an
# object before embedding it.  When we later run find-debuginfo.sh, it will
# run debugedit again.  The edits it does change the build ID bits embedded
# in the stripped object, but repeating debugedit is a no-op.  We do it
# beforehand to get the proper final build ID bits into the embedded image.
# This affects the vDSO images in vmlinux, and the vmlinux image in bzImage.
export AFTER_LINK='sh -xc "/usr/lib/rpm/debugedit -b %{buildroot} -d /usr/src/debug -i $@ > $@.id"'

cp -f %{SOURCE1} .config
echo XS_VERSION=%{version}-%{release} > .xsversion
echo XS_BASE_COMMIT=%{package_srccommit} >> .xsversion
echo XS_PQ_COMMIT=%{package_speccommit} >> .xsversion
%{?_cov_wrap} make silentoldconfig

#cp -r `pwd` ../prepared-source
#install -m 644 %{SOURCE5} ../prepared-source

%{?_cov_wrap} make %{?_smp_mflags} bzImage
%{?_cov_wrap} make %{?_smp_mflags} modules

#
# Check the kernel ABI (KABI) has not changed.
#
# The format of kernel ABI version is V.P.0+A.
#
#   V - kernel version (e.g., 3)
#   P - kernel patch level (e.g., 10)
#   A - KABI version.
#
# Note that the version does not include the sub-level version used in
# the stable kernels.  This allows the kernel updates to include the
# latest stable release without changing the KABI.
#
# ABI checking should be disabled by default for development kernels
# (those with a "0" ABI version).
#
# If this check fails you can:
#
# 1. Remove or edit patches until the ABI is the same again.
#
# 2. Remove the functions from the KABI file (if those functions are
#    guaranteed to not be used by any driver or third party module).
#    Be careful with this option.
#
# 3. Increase the ABI version (in the abi-version patch) and copy
#    the Module.symvers file from the build directory to the root of
#    the patchqueue repository and name it Module.kabi.
#
%if %{do_kabichk}
    echo "**** kABI checking is enabled in kernel SPEC file. ****"
    %{SOURCE3} -k %{SOURCE4} -s Module.symvers || exit 1
%endif

# make perf
%global perf_make \
  %{?_cov_wrap} make EXTRA_CFLAGS="${RPM_OPT_FLAGS}" LDFLAGS="%{__global_ldflags}" %{?cross_opts} V=1 NO_PERF_READ_VDSO32=1 NO_PERF_READ_VDSOX32=1 WERROR=0 HAVE_CPLUS_DEMANGLE=1 NO_GTK2=1 NO_STRLCPY=1 NO_BIONIC=1 NO_JVMTI=1 prefix=%{_prefix}
%global perf_python2 -C tools/perf PYTHON=%{__python2}
# perf
# make sure check-headers.sh is executable
chmod +x tools/perf/check-headers.sh
%{perf_make} %{perf_python2} all

pushd tools/perf/Documentation/
make %{?_smp_mflags} man
popd

%install
# Install kernel
#source %{SOURCE5}

install -d -m 755 %{buildroot}/boot
install -m 644 .config %{buildroot}/boot/config-%{uname}
install -m 644 System.map %{buildroot}/boot/System.map-%{uname}
install -m 644 arch/x86/boot/bzImage %{buildroot}/boot/vmlinuz-%{uname}
truncate -s 20M %{buildroot}/boot/initrd-%{uname}.img
ln -sf vmlinuz-%{uname} %{buildroot}/boot/vmlinuz-%{uname}-xen
ln -sf initrd-%{uname}.img %{buildroot}/boot/initrd-%{uname}-xen.img

# Install modules
# Override $(mod-fw) because we don't want it to install any firmware
# we'll get it from the linux-firmware package and we don't want conflicts
make INSTALL_MOD_PATH=%{buildroot} modules_install mod-fw=
# mark modules executable so that strip-to-file can strip them
find %{buildroot}/lib/modules/%{uname} -name "*.ko" -type f | xargs chmod u+x

install -d -m 755 %{buildroot}/lib/modules/%{uname}/extra
install -d -m 755 %{buildroot}/lib/modules/%{uname}/updates

make INSTALL_MOD_PATH=%{buildroot} vdso_install

# Save debuginfo
install -d -m 755 %{buildroot}/usr/lib/debug/lib/modules/%{uname}
install -m 755 vmlinux %{buildroot}/usr/lib/debug/lib/modules/%{uname}

# Install -headers files
make INSTALL_HDR_PATH=%{buildroot}/usr headers_install

# perf tool binary and supporting scripts/binaries
%{perf_make} %{perf_python2} DESTDIR=%{buildroot} lib=%{_lib} install-bin install-traceevent-plugins
# remove the 'trace' symlink.
rm -f %{buildroot}%{_bindir}/trace
# remove the perf-tips
rm -rf %{buildroot}%{_docdir}/perf-tip

# For both of the below, yes, this should be using a macro but right now
# it's hard coded and we don't actually want it anyway right now.
# Whoever wants examples can fix it up!

# remove examples
rm -rf %{buildroot}/usr/lib/perf/examples
# remove the stray header file that somehow got packaged in examples
rm -rf %{buildroot}/usr/lib/perf/include/bpf/

# python-perf extension
%{perf_make} %{perf_python2} DESTDIR=%{buildroot} install-python_ext

# perf man pages (note: implicit rpm magic compresses them later)
install -d %{buildroot}/%{_mandir}/man1
install -pm0644 tools/perf/Documentation/*.1 %{buildroot}/%{_mandir}/man1/

# Install -devel files
install -d -m 755 %{buildroot}%{_usrsrc}/kernels/%{uname}-%{_arch}
install -d -m 755 %{buildroot}%{_rpmconfigdir}/macros.d
install -m 644 %{SOURCE2} %{buildroot}%{_rpmconfigdir}/macros.d
echo '%%kernel_version %{uname}' >> %{buildroot}%{_rpmconfigdir}/macros.d/macros.kernel
%{?_cov_install}

# Setup -devel links correctly
ln -nsf %{srcpath} %{buildroot}/lib/modules/%{uname}/source
ln -nsf %{srcpath} %{buildroot}/lib/modules/%{uname}/build

# Copy Makefiles and Kconfigs except in some directories
paths=$(find . -path './Documentation' -prune -o -path './scripts' -prune -o -path './include' -prune -o -type f -a \( -name "Makefile*" -o -name "Kconfig*" \) -print)
cp --parents $paths %{buildroot}%{srcpath}
cp Module.symvers %{buildroot}%{srcpath}
cp System.map %{buildroot}%{srcpath}
cp .config %{buildroot}%{srcpath}
cp -a scripts %{buildroot}%{srcpath}
find %{buildroot}%{srcpath}/scripts -type f -name '*.o' -delete
cp -a tools/objtool/objtool %{buildroot}%{srcpath}/tools/objtool

cp -a --parents arch/x86/include %{buildroot}%{srcpath}
cp -a include %{buildroot}%{srcpath}/include

# files for 'make prepare' to succeed with kernel-devel
cp -a --parents arch/x86/entry/syscalls/syscall_32.tbl %{buildroot}%{srcpath}
cp -a --parents arch/x86/entry/syscalls/syscalltbl.sh %{buildroot}%{srcpath}
cp -a --parents arch/x86/entry/syscalls/syscallhdr.sh %{buildroot}%{srcpath}
cp -a --parents arch/x86/entry/syscalls/syscall_64.tbl %{buildroot}%{srcpath}
cp -a --parents arch/x86/tools/relocs_32.c %{buildroot}%{srcpath}
cp -a --parents arch/x86/tools/relocs_64.c %{buildroot}%{srcpath}
cp -a --parents arch/x86/tools/relocs.c %{buildroot}%{srcpath}
cp -a --parents arch/x86/tools/relocs_common.c %{buildroot}%{srcpath}
cp -a --parents arch/x86/tools/relocs.h %{buildroot}%{srcpath}
cp -a --parents tools/include/tools/le_byteshift.h %{buildroot}%{srcpath}
cp -a --parents arch/x86/purgatory/purgatory.c %{buildroot}%{srcpath}
cp -a --parents arch/x86/purgatory/stack.S %{buildroot}%{srcpath}
#cp -a --parents arch/x86/purgatory/string.c %{buildroot}%{srcpath}
cp -a --parents arch/x86/purgatory/setup-x86_64.S %{buildroot}%{srcpath}
cp -a --parents arch/x86/purgatory/entry64.S %{buildroot}%{srcpath}
cp -a --parents arch/x86/boot/string.h %{buildroot}%{srcpath}
cp -a --parents arch/x86/boot/string.c %{buildroot}%{srcpath}
cp -a --parents arch/x86/boot/ctype.h %{buildroot}%{srcpath}

# Copy .config to include/config/auto.conf so "make prepare" is unnecessary.
cp -a %{buildroot}%{srcpath}/.config %{buildroot}%{srcpath}/include/config/auto.conf

# Make sure the Makefile and version.h have a matching timestamp so that
# external modules can be built
touch -r %{buildroot}%{srcpath}/Makefile %{buildroot}%{srcpath}/include/generated/uapi/linux/version.h

find %{buildroot} -name '.*.cmd' -type f -delete

# Install files for building live patches
#mv ../prepared-source %{buildroot}%{lp_devel_dir}
#install -m 644 vmlinux %{buildroot}%{lp_devel_dir}

%post
> %{_localstatedir}/lib/rpm-state/regenerate-initrd-%{name}-%{uname}

depmod -ae -F /boot/System.map-%{uname} %{uname}

if [ $1 == 1 ]; then
    # Add grub entry upon initial installation if the package is installed manually
    # During system installation, the bootloader isn't installed yet so grub is updated as a later task.
    if [ -f /boot/grub/grub.cfg -o -f /boot/efi/EFI/xenserver/grub.cfg ]; then
        /opt/xensource/bin/updategrub.py add kernel-alt %{uname}
    else
        echo "Skipping grub configuration during host installation."
    fi
else
    # Package update: we delay the update until posttrans to let the old package postun 
    # store version information in a temporary file
    > %{_localstatedir}/lib/rpm-state/update-grub-for-%{name}-%{uname}
fi

%posttrans
depmod -ae -F /boot/System.map-%{uname} %{uname}

if [ -e %{_localstatedir}/lib/rpm-state/regenerate-initrd-%{name}-%{uname} ]; then
    rm %{_localstatedir}/lib/rpm-state/regenerate-initrd-%{name}-%{uname}
    dracut -f /boot/initrd-%{uname}.img %{uname}
fi

if [ -e %{_localstatedir}/lib/rpm-state/update-grub-for-%{name}-%{uname} ]; then
    # The package has been updated: consider updating grub
    rm %{_localstatedir}/lib/rpm-state/update-grub-for-%{name}-%{uname}
    # Get the version from the file the postun script from the uninstalled RPM wrote, if any
    if [ -e %{_localstatedir}/lib/rpm-state/%{name}-uninstall-version ]; then
        OLDVERSION=$(cat %{_localstatedir}/lib/rpm-state/%{name}-uninstall-version)
        rm %{_localstatedir}/lib/rpm-state/%{name}-uninstall-version
        if [ "$OLDVERSION" != %{uname} ]; then
            /opt/xensource/bin/updategrub.py replace kernel-alt %{uname} --old-version $OLDVERSION
        fi
    else
        # No file? Then we are probably upgrading an old kernel-alt package
        # It can be either 4.19.102-4 from 8.1 RC1, or an older one
        # If it's 4.19.102-4 then there will be a grub entry to replace
        # Else there won't be (except if manually added)
        # The following will replace the entry if exists or just add the new one if not
        /opt/xensource/bin/updategrub.py replace kernel-alt %{uname} --old-version 4.19.102 --ignore-missing
    fi
fi


%postun
if [ $1 == 0 ]; then
    # remove grub entry upon uninstallation
    /opt/xensource/bin/updategrub.py remove kernel-alt %{uname} --ignore-missing
else
    # write current version in a file for the upgraded RPM posttrans to handle grub config update
    echo %{uname} > %{_localstatedir}/lib/rpm-state/%{name}-uninstall-version
fi

%files
/boot/vmlinuz-%{uname}
/boot/vmlinuz-%{uname}-xen
/boot/initrd-%{uname}-xen.img
%ghost /boot/initrd-%{uname}.img
/boot/System.map-%{uname}
/boot/config-%{uname}
%dir /lib/modules/%{uname}
/lib/modules/%{uname}/extra
/lib/modules/%{uname}/kernel
/lib/modules/%{uname}/modules.order
/lib/modules/%{uname}/modules.builtin
/lib/modules/%{uname}/updates
/lib/modules/%{uname}/vdso
%exclude /lib/modules/%{uname}/vdso/.build-id
%ghost /lib/modules/%{uname}/modules.alias
%ghost /lib/modules/%{uname}/modules.alias.bin
%ghost /lib/modules/%{uname}/modules.builtin.bin
%ghost /lib/modules/%{uname}/modules.dep
%ghost /lib/modules/%{uname}/modules.dep.bin
%ghost /lib/modules/%{uname}/modules.devname
%ghost /lib/modules/%{uname}/modules.softdep
%ghost /lib/modules/%{uname}/modules.symbols
%ghost /lib/modules/%{uname}/modules.symbols.bin
%doc COPYING
%doc LICENSES/preferred/GPL-2.0
%doc LICENSES/exceptions/Linux-syscall-note
%doc Documentation/process/license-rules.rst

%files headers
/usr/include/*

%files devel
/lib/modules/%{uname}/build
/lib/modules/%{uname}/source
%verify(not mtime) /usr/src/kernels/%{uname}-%{_arch}
%{_rpmconfigdir}/macros.d/macros.kernel

%files -n perf-alt
%{_bindir}/perf
%dir %{_libdir}/traceevent
%{_libdir}/traceevent/plugins/
%{_libexecdir}/perf-core
%{_datadir}/perf-core/
%{_mandir}/man[1-8]/perf*
%{_sysconfdir}/bash_completion.d/perf
%doc tools/perf/Documentation/examples.txt
%license COPYING

%files -n python2-perf-alt
%license COPYING
%{python2_sitearch}/*

#%files lp-devel_%{version}_%{release}
#%{lp_devel_dir}

%{?_cov_results_package}

%changelog
* Thu Apr 04 2024 Yann Dirson <yann.dirson@vates.tech> - 4.19.227-6
- Stop overruling interpreter in updategrub.py

* Mon Feb 05 2024 Yann Dirson <yann.dirson@vates.tech> - 4.19.227-5
- Use updategrub.py from /opt/xensource/bin

* Thu Oct 06 2022 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.19.227-4
- Don't provide kernel Provides
- We don't want kernel-alt to be pulled as build deps instead of main kernel packages

* Fri Sep 30 2022 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.19.227-3
- Rebuild for XCP-ng 8.3 alpha

* Fri May 13 2022 Andrew Lindh <andrew@netplex.net> - 4.19.227-2
- Fix UEFI Dom0 boot EFIFB with 64 bit BAR from Xen (backport from kernel 5.17)

* Thu Feb 03 2022 Rushikesh Jadhav <rushikesh7@gmail.com> - 4.19.227-1
- Fixes issue #522
- Cumulative update till 4.19.227
- Disabled Citrix patches that were taken from upstream
- Disabled GFS2 and gvt patches as its not support by the distro

* Thu Apr 01 2021 Rushikesh Jadhav <rushikesh7@gmail.com> - 4.19.154-1
- Security (XSAs 367 and 371) and bugfix update
- XSA-367: Linux: netback fails to honor grant mapping errors
- XSA-371: Linux: blkback driver may leak persistent grants
- Patches backported from linus kernel to fix event-related issues caused by XSA-332
- Update patch level to 4.19.154

* Tue Mar 02 2021 Rushikesh Jadhav <rushikesh7@gmail.com> - 4.19.142-3
- Security update
- Fix XSAs 361 362 365
- Fix use-after-free in xen-netback caused by XSA-332
- See https://xenbits.xen.org/xsa/
- Updated to patch-4.19.93-94-mod to resolve XSA 365 conflict

* Wed Dec 23 2020 Rushikesh Jadhav <rushikesh7@gmail.com> - 4.19.142-2
- Fix https://github.com/xcp-ng/xcp/issues/468

* Mon Nov 02 2020 Rushikesh Jadhav <rushikesh7@gmail.com> - 4.19.142-1
- Add fix for XSA-331 from kernel package
- Add fix for XSA-332 from kernel package
- Update patch level to 4.19.142

* Wed Aug 19 2020 Rushikesh Jadhav <rushikesh7@gmail.com> - 4.19.140-1
- Update patch level to 4.19.140
- Enable Kernel modules to support Wireless, Dell RBU
- Enable NTFS RW

* Sat Aug 15 2020 Rushikesh Jadhav <rushikesh7@gmail.com> - 4.19.138-1
- Update patch level to 4.19.138

* Tue Jun 30 2020 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.19.19-7.0.7.1
- Update for XCP-ng 8.2

* Tue May 12 2020 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-7.0.7
- CA-339209: Stop building Intel ME drivers and remove MEI from kABI
- CP-31860: Backport GFS2 & DLM modules from v5.7-rc2
- CP-31860: gfs2: Add some v5.7 for-rc5 patches
- CA-338613: Fix busy wait in DLM

* Thu Apr 30 2020 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-7.0.6
- CA-337406: Disable EFI pstore backend by default
- CA-338183: Optimize get_random_u{32,64} by removing calls to RDRAND
- CA-308055: Fix an iSCSI use-after-free

* Mon Apr 20 2020 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-7.0.5
- CA-337460 - Allow commit lists to be imported chronologically.
- Replace patch with upstream backport

* Thu Mar 26 2020 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-7.0.4
- CA-335089, CP-33195: Move PV-IOMMU 1-1 map initialization to Xen
- Restore PV-IOMMU kABI
- CA-337060: Restore best effort unmaps to avoid clashes with reserved regions

* Mon Mar 09 2020 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-7.0.3
- CA-334001: Revert upstream fix for CA-306398 since it's not complete
- CA-332618: Fix several FCoE memory leaks
- Replace i915 patches with backports
- CA-335769: xen-netback: Handle unexpected map grant ref return value

* Fri Feb 21 2020 Steven Woods <steven.woods@citrix.com> - 4.19.19-7.0.2
- CP33120: Add Coverity build macros

* Thu Jan 23 2020 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-7.0.1
- CA-333532: Fix patch context
- CA-332867: Fix i915 late loading failure due to memory fragmentation

* Wed Jan 08 2020 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-7.0.0
- Replace paches with backports and some clean up
- CA-332663: Fix TDR while using latest Intel guest driver with GVT-g
- Remove XenGT symbols from kABI
- CA-332782: backport fixes for blkdiscard bugs

* Thu Nov 28 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-6.0.9
- CA-330853: Fix memory corruption on BPDU processing

* Thu Oct 24 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-6.0.8
- CP-28248: Build PV frontends inside the kernel image

* Thu Sep 26 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-6.0.7
- CA-326847: Fixes for checksum calculation in mlx drivers
- Enable PVH support in Dom0 kernel
- CA-325955: Fix SR-IOV VF init if MCFG is not reserved in E820
- Extend DRM_I915_GEM_VGTBUFFER support to more architectures
- CA-327274: x86/efi: Don't require non-blocking EFI callbacks

* Fri Aug 23 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-6.0.6
- CA-325320: Disable the pcc_cpufreq module

* Mon Aug 12 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-6.0.5
- CA-320186: Make bnx2fc setup FCoE reliably
- CA-324731: xen/netback: Reset nr_frags before freeing skb
- Backport some GFS2 fixes
- Backport patches from upstream

* Wed Jun 26 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-6.0.4
- CA-322114: Fix TCP SACK/MSS vulnerabilites - CVE-2019-1147[7-9]
- CA-322114: Backport follow-up patch for CVE-2019-11478

* Wed Jun 19 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-6.0.3
- CA-320089: Fix issues from GFS2 backports
- CA-319469: Avoid amd64_edac_mod loading failures on AMD EPYC machines
- CA-315930: xfs: Avoid deadlock when backed by tapdisk
- Replace a patch with an upstream backport

* Mon Jun 10 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-6.0.2
- CA-320214: Mitigate OVMF triple-fault due to GVT-g BAR mapping timeout

* Tue May 28 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-6.0.1
- Replace some local GFS2 patches with backports
- gfs2: Restore kABI changes

* Fri Apr 12 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-6.0.0
- Replace patches with backports
- CA-314807: Fix buffer overflow in privcmd ioctl

* Fri Mar 22 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-5.0.8
- CA-309637: gfs2: Take log_flush lock during recovery

* Wed Mar 20 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-5.0.7
- CA-310966: gfs2: Avoid deadlocking in gfs2_log_flush

* Mon Mar 18 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-5.0.6
- CA-312608: blktap2: Don't change the elevator

* Mon Mar 11 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-5.0.5
- CA-312266: fix missed wakeups in GFS2
- Replace patches with backports

* Thu Mar 07 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-5.0.4
- CP-30827: Set ABI version to 1 and turn on kABI checking
- CA-310995: Disable hung task warnings for the idle IO scheduling class
- CA-311463: Fix occasional leak of grant ref mappings under memory pressure

* Wed Feb 27 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-5.0.3
- CA-311278: Fix skbuff_head_cache corruption in IPv4 fragmentation
- CA-311302: Backport a fix for CVE-2019-8912
- CA-310396: blktap2: Fix setting the elevator to noop

* Tue Feb 19 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-5.0.2
- CA-310859: Only use pfn_to_bfn if PV-IOMMU is not in operation
- CP-30503: Switch accepted into 4.19+ local patches to backports in the patchqueue

* Thu Feb 14 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.19.19-5.0.1
- Misc bugfixes

* Tue Oct 30 2018 Jennifer Herbert <jennifer.herbert@citrix.com> - 4.19
- Update kernel to 4.19

* Fri Sep 28 2018 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.4.52-4.1.0
- CA-296112: Mitigate against CVE-2018-5391
- Add GFS2 resource group skippiness patch
- GFS2: avoid recently demoted resource groups

* Fri Aug 10 2018 Simon Rowe <simon.rowe@citrix.com> - 4.4.52-4.0.12
- CA-295418: Fix initially incorrect GVT-g patch forwardport

* Fri Aug 03 2018 Simon Rowe <simon.rowe@citrix.com> - 4.4.52-4.0.11
- Add XSA-274 patch
- Backport L1TF mitigations from v4.18
- CA-295106: Add xsa270.patch

* Fri Jul 27 2018 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.4.52-4.0.10
- CA-288640: Silence xen_watchdog spam
- CA-290024: add sysfs node to allow toolstack to wait
- CA-294295: Fix Intel CQM when running under Xen
- CA-287658: Fix iscsi_complete_task() race

* Wed May 30 2018 Simon Rowe <simon.rowe@citrix.com> - 4.4.52-4.0.9
- Backport CIFS: Reconnect expired SMB sessions (partial)
- CIFS: Handle STATUS_USER_SESSION_DELETED

* Tue May 15 2018 Simon Rowe <simon.rowe@citrix.com> - 4.4.52-4.0.8
- Backport DLM changes from 4.16
- Backport GFS2 from 4.15

* Mon Apr 16 2018 Simon Rowe <simon.rowe@citrix.com> - 4.4.52-4.0.7
- CA-287508: Fix for skb_warn_bad_offload()

* Mon Apr 09 2018 Simon Rowe <simon.rowe@citrix.com> - 4.4.52-4.0.6
- CA-286864: Fixup blktap blkdevice's elevator to noop

* Wed Mar 28 2018 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.4.52-4.0.4
- CA-277853: Reduce skb_warn_bad_offload noise.
- CA-286713: scsi: devinfo: Add Microsoft iSCSI target to 1024 sector blacklist
- CA-286719: Fixup locking in __iscsi_conn_send_pdu
- CP-26829: Use DMOP rather than HVMOP

* Thu Feb 01 2018 Simon Rowe <simon.rowe@citrix.com> - 4.4.52-4.0.3
- Bump DOMCTL interface version for Xen 4.11
- CP-26571: Backport GFS2 from v4.14.12
- CP-26571: Backport DLM from v4.14.12

* Wed Jan 10 2018 Simon Rowe <simon.rowe@citrix.com> - 4.4.52-4.0.2
- CA-275523: Use the correct firmware for bfa

* Thu Dec 07 2017 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.4.52-4.0.1
- CA-273824: Print name of delayed work, to debug a crash
- CA-273693: Fix retrieving information using scsi_id
- CA-275730: Fix partial gntdev_mmap() cleanup

* Tue Nov 07 2017 Simon Rowe <simon.rowe@citrix.com> - 4.4.52-3.1.9
- CA-269705: [cifs] fix echo infinite loop when session needs reconnect
- CA-270775: Backport, gntdev out of bounds access avoidance, patch

* Mon Oct 23 2017 Simon Rowe <simon.rowe@citrix.com> - 4.4.52-3.1.8
- CA-270432: Backport a fix for a deadlock in libfc

* Mon Oct 16 2017 Simon Rowe <simon.rowe@citrix.com> - 4.4.52-3.1.7
- CA-265082 Disabling DM-MQ as it is not production ready in 4.4 kernel
- CA-268107: Fix various races in ipset

* Tue Sep 05 2017 Simon Rowe <simon.rowe@citrix.com> - 4.4.52-3.1.6
- Remove kernel.spec
- CA-255214: Do not scrub ignore_df for tunnels
- CA-255214: Enable fragemention of GRE packets
- CA-261981: Backport fix for iSCSI crash

* Tue Aug 22 2017 Simon Rowe <simon.rowe@citrix.com> - 4.4.52-3.1.5
- CA-261171: XSA-229 - Fix Xen block IO merge-ability calculation

* Wed May 17 2017 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.4.52-3.1
- Rewrote spec file.
