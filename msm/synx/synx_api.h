/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2019, 2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2023, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef __SYNX_API_H__
#define __SYNX_API_H__

#include <linux/list.h>
#include <synx_header.h>

#include "synx_err.h"

#define SYNX_NO_TIMEOUT        ((u64)-1)

/**
 * SYNX_INVALID_HANDLE      : client can assign the synx handle variable with this value
 *                            when it doesn't hold a valid synx handle
 */
#define SYNX_INVALID_HANDLE 0

#define SYNX_HW_FENCE_CLIENT_START 1024
#define SYNX_HW_FENCE_CLIENT_END 4096
#define SYNX_MAX_SIGNAL_PER_CLIENT 64

/**
 * enum synx_create_flags - Flags passed during synx_create call
 *
 * SYNX_CREATE_LOCAL_FENCE  : Instructs the framework to create local synx object
 * SYNX_CREATE_GLOBAL_FENCE : Instructs the framework to create global synx object
 * SYNX_CREATE_DMA_FENCE    : Create a synx object by wrapping the provided dma fence.
 *                            Need to pass the dma_fence ptr through fence variable
 *                            if this flag is set.
 * SYNX_CREATE_CSL_FENCE    : Create a synx object with provided csl fence.
 *                            Establishes interop with the csl fence through
 *                            bind operations.
 */
enum synx_create_flags {
	SYNX_CREATE_LOCAL_FENCE  = 0x01,
	SYNX_CREATE_GLOBAL_FENCE = 0x02,
	SYNX_CREATE_DMA_FENCE    = 0x04,
	SYNX_CREATE_CSL_FENCE    = 0x08,
	SYNX_CREATE_MAX_FLAGS    = 0x10,
};

/**
 * enum synx_init_flags - Session initialization flag
 */
enum synx_init_flags {
	SYNX_INIT_MAX = 0x01,
};

/**
 * enum synx_import_flags - Import flags
 *
 * SYNX_IMPORT_LOCAL_FENCE  : Instructs the framework to create local synx object
 * SYNX_IMPORT_GLOBAL_FENCE : Instructs the framework to create global synx object
 * SYNX_IMPORT_SYNX_FENCE   : Import native Synx handle for synchronization
 *                            Need to pass the Synx handle ptr through fence variable
 *                            if this flag is set.
 * SYNX_IMPORT_DMA_FENCE    : Import dma fence.and crate Synx handle for interop
 *                            Need to pass the dma_fence ptr through fence variable
 *                            if this flag is set.
 * SYNX_IMPORT_EX_RELEASE   : Flag to inform relaxed invocation where release call
 *                            need not be called by client on this handle after import.
 */
enum synx_import_flags {
	SYNX_IMPORT_LOCAL_FENCE  = 0x01,
	SYNX_IMPORT_GLOBAL_FENCE = 0x02,
	SYNX_IMPORT_SYNX_FENCE   = 0x04,
	SYNX_IMPORT_DMA_FENCE    = 0x08,
	SYNX_IMPORT_EX_RELEASE   = 0x10,
};

/**
 * enum synx_signal_status - Signal status
 *
 * SYNX_STATE_SIGNALED_SUCCESS : Signal success
 * SYNX_STATE_SIGNALED_CANCEL  : Signal cancellation
 * SYNX_STATE_SIGNALED_MAX     : Clients can send custom notification
 *                               beyond the max value (only positive)
 */
enum synx_signal_status {
	SYNX_STATE_SIGNALED_SUCCESS = 2,
	SYNX_STATE_SIGNALED_CANCEL  = 4,
	SYNX_STATE_SIGNALED_MAX     = 64,
};

/**
 * synx_callback - Callback invoked by external fence
 *
 * External fence dispatch the registered callback to notify
 * signal to synx framework.
 */
typedef void (*synx_callback)(s32 sync_obj, int status, void *data);

/**
 * synx_user_callback - Callback function registered by clients
 *
 * User callback registered for non-blocking wait. Dispatched when
 * synx object is signaled or timeout has expired.
 */
typedef void (*synx_user_callback_t)(u32 h_synx, int status, void *data);

/**
 * struct bind_operations - Function pointers that need to be defined
 *    to achieve bind functionality for external fence with synx obj
 *
 * @register_callback   : Function to register with external sync object
 * @deregister_callback : Function to deregister with external sync object
 * @enable_signaling    : Function to enable the signaling on the external
 *                        sync object (optional)
 * @signal              : Function to signal the external sync object
 */
struct bind_operations {
	int (*register_callback)(synx_callback cb_func,
		void *userdata, s32 sync_obj);
	int (*deregister_callback)(synx_callback cb_func,
		void *userdata, s32 sync_obj);
	int (*enable_signaling)(s32 sync_obj);
	int (*signal)(s32 sync_obj, u32 status);
};

/**
 * synx_bind_client_type : External fence supported for bind
 *
 * SYNX_TYPE_CSL : Camera CSL fence
 */
enum synx_bind_client_type {
	SYNX_TYPE_CSL = 0,
	SYNX_MAX_BIND_TYPES,
};

/**
 * struct synx_register_params - External registration parameters
 *
 * @ops  : Bind operations struct
 * @name : External client name
 *         Only first 64 bytes are accepted, rest will be ignored
 * @type : Synx bind client type
 */
struct synx_register_params {
	struct bind_operations ops;
	char *name;
	enum synx_bind_client_type type;
};

/**
 * struct synx_queue_desc - Memory descriptor of the queue allocated by
 *                           the fence driver for each client during
 *                           register.
 *
 * @vaddr    : CPU virtual address of the queue.
 * @dev_addr : Physical address of the memory object.
 * @size     : Size of the memory.
 * @mem_data : Internal pointer with the attributes of the allocation.
 */
struct synx_queue_desc {
	void *vaddr;
	u64 dev_addr;
	u64 size;
	void *mem_data;
};

/**
 * enum synx_client_id : Unique identifier of the supported clients
 *
 * @SYNX_CLIENT_NATIVE   : Native Client
 * @SYNX_CLIENT_GFX_CTX0 : GFX Client 0
 * @SYNX_CLIENT_DPU_CTL0 : DPU Client 0
 * @SYNX_CLIENT_DPU_CTL1 : DPU Client 1
 * @SYNX_CLIENT_DPU_CTL2 : DPU Client 2
 * @SYNX_CLIENT_DPU_CTL3 : DPU Client 3
 * @SYNX_CLIENT_DPU_CTL4 : DPU Client 4
 * @SYNX_CLIENT_DPU_CTL5 : DPU Client 5
 * @SYNX_CLIENT_EVA_CTX0 : EVA Client 0
 * @SYNX_CLIENT_VID_CTX0 : Video Client 0
 * @SYNX_CLIENT_NSP_CTX0 : NSP Client 0
 * @SYNX_CLIENT_IFE_CTX0 : IFE Client 0
 * @SYNX_CLIENT_ICP_CTX0 : ICP Client 0
 * @SYNX_CLIENT_HW_FENCE_GFX_CTX0 : HW Fence GFX Client 0
 * @SYNX_CLIENT_HW_FENCE_IPE_CTX0 : HW Fence IPE Client 0
 * @SYNX_CLIENT_HW_FENCE_VID_CTX0 : HW Fence Video Client 0
 * @SYNX_CLIENT_HW_FENCE_DPU0_CTL0 : HW Fence DPU0 Client 0
 * @SYNX_CLIENT_HW_FENCE_DPU1_CTL0 : HW Fence DPU1 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE0_CTX0 : HW Fence IFE0 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE1_CTX0 : HW Fence IFE1 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE2_CTX0 : HW Fence IFE2 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE3_CTX0 : HW Fence IFE3 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE4_CTX0 : HW Fence IFE4 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE5_CTX0 : HW Fence IFE5 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE6_CTX0 : HW Fence IFE6 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE7_CTX0 : HW Fence IFE7 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE8_CTX0 : HW Fence IFE8 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE9_CTX0 : HW Fence IFE9 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE10_CTX0 : HW Fence IFE10 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE11_CTX0 : HW Fence IFE11 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE12_CTX0 : HW Fence IFE12 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE13_CTX0 : HW Fence IFE13 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE14_CTX0 : HW Fence IFE14 Client 0
 * @SYNX_CLIENT_HW_FENCE_IFE15_CTX0 : HW Fence IFE15 Client 0
 */
enum synx_client_id {
	SYNX_CLIENT_NATIVE = 0,
	SYNX_CLIENT_GFX_CTX0,
	SYNX_CLIENT_DPU_CTL0,
	SYNX_CLIENT_DPU_CTL1,
	SYNX_CLIENT_DPU_CTL2,
	SYNX_CLIENT_DPU_CTL3,
	SYNX_CLIENT_DPU_CTL4,
	SYNX_CLIENT_DPU_CTL5,
	SYNX_CLIENT_EVA_CTX0,
	SYNX_CLIENT_VID_CTX0,
	SYNX_CLIENT_NSP_CTX0,
	SYNX_CLIENT_IFE_CTX0,
	SYNX_CLIENT_ICP_CTX0,
	SYNX_CLIENT_HW_FENCE_GFX_CTX0 = SYNX_HW_FENCE_CLIENT_START,
	SYNX_CLIENT_HW_FENCE_IPE_CTX0 = SYNX_CLIENT_HW_FENCE_GFX_CTX0 + SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_VID_CTX0 = SYNX_CLIENT_HW_FENCE_IPE_CTX0 + SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_DPU0_CTL0 = SYNX_CLIENT_HW_FENCE_VID_CTX0 + SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_DPU1_CTL0 = SYNX_CLIENT_HW_FENCE_DPU0_CTL0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE0_CTX0 = SYNX_CLIENT_HW_FENCE_DPU1_CTL0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE1_CTX0 = SYNX_CLIENT_HW_FENCE_IFE0_CTX0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE2_CTX0 = SYNX_CLIENT_HW_FENCE_IFE1_CTX0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE3_CTX0 = SYNX_CLIENT_HW_FENCE_IFE2_CTX0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE4_CTX0 = SYNX_CLIENT_HW_FENCE_IFE3_CTX0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE5_CTX0 = SYNX_CLIENT_HW_FENCE_IFE4_CTX0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE6_CTX0 = SYNX_CLIENT_HW_FENCE_IFE5_CTX0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE7_CTX0 = SYNX_CLIENT_HW_FENCE_IFE6_CTX0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE8_CTX0 = SYNX_CLIENT_HW_FENCE_IFE7_CTX0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE9_CTX0 = SYNX_CLIENT_HW_FENCE_IFE8_CTX0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE10_CTX0 = SYNX_CLIENT_HW_FENCE_IFE9_CTX0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE11_CTX0 = SYNX_CLIENT_HW_FENCE_IFE10_CTX0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE12_CTX0 = SYNX_CLIENT_HW_FENCE_IFE11_CTX0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE13_CTX0 = SYNX_CLIENT_HW_FENCE_IFE12_CTX0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE14_CTX0 = SYNX_CLIENT_HW_FENCE_IFE13_CTX0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_HW_FENCE_IFE15_CTX0 = SYNX_CLIENT_HW_FENCE_IFE14_CTX0 +
		SYNX_MAX_SIGNAL_PER_CLIENT,
	SYNX_CLIENT_MAX = SYNX_HW_FENCE_CLIENT_END,
};

struct synx_ops;

/**
 * struct synx_session - Client session identifier
 *
 * @type   : Session type
 * @client : Pointer to client session
 * @ops    : Pointer to synx operations
 */
struct synx_session {
	u32 type;
	void *client;
	const struct synx_ops *ops;
};

/**
 * struct synx_initialization_params - Session params
 *
 * @name  : Client session name
 *          Only first 64 bytes are accepted, rest will be ignored
 * @ptr   : Pointer to queue descriptor (filled by function)
 * @id    : Client identifier
 * @flags : Synx initialization flags
 */
struct synx_initialization_params {
	const char *name;
	struct synx_queue_desc *ptr;
	enum synx_client_id id;
	enum synx_init_flags flags;
};

/**
 * struct synx_create_params - Synx creation parameters
 *
 * @name     : Optional parameter associating a name with the synx
 *             object for debug purposes
 *             Only first 64 bytes are accepted,
 *             rest will be ignored
 * @h_synx   : Pointer to synx object handle (filled by function)
 * @fence    : Pointer to external fence
 * @flags    : Synx flags for customization (mentioned below)
 *
 * SYNX_CREATE_GLOBAL_FENCE - Hints the framework to create global synx object
 *     If flag not set, hints framework to create a local synx object.
 * SYNX_CREATE_DMA_FENCE - Wrap synx object with dma fence.
 *     Need to pass the dma_fence ptr through 'fence' variable if this flag is set.
 * SYNX_CREATE_BIND_FENCE - Create a synx object with provided external fence.
 *     Establishes interop with supported external fence through bind operations.
 *     Need to fill synx_external_desc structure if this flag is set.
 */

struct synx_create_params {
	const char *name;
	u32 *h_synx;
	void *fence;
	enum synx_create_flags flags;
};

/**
 * enum synx_merge_flags - Handle merge flags
 *
 * SYNX_MERGE_LOCAL_FENCE   : Create local composite object.
 * SYNX_MERGE_GLOBAL_FENCE  : Create global composite object.
 * SYNX_MERGE_NOTIFY_ON_ALL : Notify on signaling of ALL objects
 * SYNX_MERGE_NOTIFY_ON_ANY : Notify on signaling of ANY object
 */
enum synx_merge_flags {
	SYNX_MERGE_LOCAL_FENCE   = 0x01,
	SYNX_MERGE_GLOBAL_FENCE  = 0x02,
	SYNX_MERGE_NOTIFY_ON_ALL = 0x04,
	SYNX_MERGE_NOTIFY_ON_ANY = 0x08,
};

/*
 * struct synx_merge_params - Synx merge parameters
 *
 * @h_synxs      : Pointer to a array of synx handles to be merged
 * @flags        : Merge flags
 * @num_objs     : Number of synx objs in the block
 * @h_merged_obj : Merged synx object handle (filled by function)
 */
struct synx_merge_params {
	u32 *h_synxs;
	enum synx_merge_flags flags;
	u32 num_objs;
	u32 *h_merged_obj;
};

/**
 * enum synx_import_type - Import type
 *
 * SYNX_IMPORT_INDV_PARAMS : Import filled with synx_import_indv_params struct
 * SYNX_IMPORT_ARR_PARAMS  : Import filled with synx_import_arr_params struct
 */
enum synx_import_type {
	SYNX_IMPORT_INDV_PARAMS = 0x01,
	SYNX_IMPORT_ARR_PARAMS  = 0x02,
};

/**
 * struct synx_import_indv_params - Synx import indv parameters
 *
 * @new_h_synxs : Pointer to new synx object
 *                (filled by the function)
 *                The new handle/s should be used by importing
 *                process for all synx api operations and
 *                for sharing with FW cores.
 * @flags       : Synx flags
 * @fence       : Pointer to external fence
 */
struct synx_import_indv_params {
	u32 *new_h_synx;
	enum synx_import_flags flags;
	void *fence;
};

/**
 * struct synx_import_arr_params - Synx import arr parameters
 *
 * @list        : Array of synx_import_indv_params pointers
 * @num_fences  : No of fences passed to framework
 */
struct synx_import_arr_params {
	struct synx_import_indv_params *list;
	u32 num_fences;
};

/**
 * struct synx_import_params - Synx import parameters
 *
 * @type : Import params type filled by client
 * @indv : Params to import an individual handle/fence
 * @arr  : Params to import an array of handles/fences
 */
struct synx_import_params {
	enum synx_import_type type;
	union {
		struct synx_import_indv_params indv;
		struct synx_import_arr_params  arr;
	};
};

/**
 * struct synx_callback_params - Synx callback parameters
 *
 * @h_synx         : Synx object handle
 * @cb_func        : Pointer to callback func to be invoked
 * @userdata       : Opaque pointer passed back with callback
 * @cancel_cb_func : Pointer to callback to ack cancellation (optional)
 * @timeout_ms     : Timeout in ms. SYNX_NO_TIMEOUT if no timeout.
 */
struct synx_callback_params {
	u32 h_synx;
	synx_user_callback_t cb_func;
	void *userdata;
	synx_user_callback_t cancel_cb_func;
	u64 timeout_ms;
};

/**
 * struct synx_ops - Synx operations
 *
 * @uninitialize        : destroys the client session
 * @create              : creates synx object
 * @async_wait          : registers a callback with synx object
 * @cancel_async_wait   : de-registers a callback with synx oject
 * @signal              : signals synx object
 * @signal_n            : signals n synx objects
 * @merge               : merges multiple synx objects
 * @wait                : waits for a synx object synchronously
 * @read_n              : reads n synx objects
 * @get_status          : returns status of synx object
 * @import              : imports (looks up) synx object from given handle/fence
 * @get_fence           : gets native fence backing synx object
 * @release             : releases synx object
 */
struct synx_ops {
	int (*uninitialize)(struct synx_session *session);
	int (*create)(struct synx_session *session, struct synx_create_params *params);
	int (*async_wait)(struct synx_session *session, struct synx_callback_params *params);
	int (*cancel_async_wait)(struct synx_session *session, struct synx_callback_params *params);
	int (*signal)(struct synx_session *session, u32 h_synx, enum synx_signal_status status);
	int (*signal_n)(struct synx_session *session, u32 *h_synx, u32 h_synx_count,
			enum synx_signal_status *status, int *h_synx_error);
	int (*merge)(struct synx_session *session, struct synx_merge_params *params);
	int (*wait)(struct synx_session *session, u32 h_synx, u64 timeout_ms);
	int (*read_n)(struct synx_session *session, u32 *h_synx, u32 h_synx_count,
			enum synx_signal_status *status, int *h_synx_error, u64 timeout_ms);
	int (*get_status)(struct synx_session *session, u32 h_synx);
	int (*import)(struct synx_session *session, struct synx_import_params *params);
	void *(*get_fence)(struct synx_session *session, u32 h_synx);
	int (*release)(struct synx_session *session, u32 h_synx);
};

/* Kernel APIs */

/* synx_register_ops - Register operations for external synchronization
 *
 * Register with synx for enabling external synchronization through bind
 *
 * @param params : Pointer to register params
 *
 * @return Status of operation. SYNX_SUCCESS in case of success.
 * -SYNX_INVALID will be returned if params are invalid.
 * -SYNX_NOMEM will be returned if bind ops cannot be registered due to
 * insufficient memory.
 * -SYNX_ALREADY will be returned if type already in use.
 */
int synx_register_ops(const struct synx_register_params *params);

/**
 * synx_deregister_ops - De-register external synchronization operations
 *
 * @param params : Pointer to register params
 *
 * @return Status of operation. SYNX_SUCCESS in case of success.
 * -SYNX_INVALID will be returned if record not found.
 */
int synx_deregister_ops(const struct synx_register_params *params);

/**
 * synx_initialize - Initializes a new client session
 *
 * @param params : Pointer to session init params
 *
 * @return Client session pointer on success. NULL or error in case of failure.
 */
struct synx_session *synx_initialize(struct synx_initialization_params *params);

/**
 * synx_uninitialize - Destroys the client session
 *
 * @param session : Session ptr (returned from synx_initialize)
 *
 * @return Status of operation. SYNX_SUCCESS in case of success.
 */
int synx_uninitialize(struct synx_session *session);

/**
 * synx_create - Creates a synx object
 *
 *  Creates a new synx obj and returns the handle to client.
 *
 * @param session : Session ptr (returned from synx_initialize)
 * @param params  : Pointer to create params
 *
 * @return Status of operation. SYNX_SUCCESS in case of success.
 * -SYNX_INVALID will be returned if params were invalid.
 * -SYNX_NOMEM will be returned if the kernel can't allocate space for
 * synx object.
 */
int synx_create(struct synx_session *session, struct synx_create_params *params);

/**
 * synx_async_wait - Registers a callback with a synx object
 *
 * @param session : Session ptr (returned from synx_initialize)
 * @param params  : Callback params
 *
 * @return Status of operation. SYNX_SUCCESS in case of success.
 * -SYNX_INVALID will be returned if userdata is invalid.
 * -SYNX_NOMEM will be returned if cb_func is invalid.
 */
int synx_async_wait(struct synx_session *session, struct synx_callback_params *params);

/**
 * synx_cancel_async_wait - De-registers a callback with a synx object
 *
 * @param session : Session ptr (returned from synx_initialize)
 * @param params  : Callback params
 *
 * @return Status of operation. SYNX_SUCCESS in case of success.
 * -SYNX_ALREADY if object has already been signaled, and cannot be cancelled.
 * -SYNX_INVALID will be returned if userdata is invalid.
 * -SYNX_NOMEM will be returned if cb_func is invalid.
 */
int synx_cancel_async_wait(struct synx_session *session,
	struct synx_callback_params *params);

/**
 * synx_signal - Signals a synx object with the status argument.
 *
 * This function will signal the synx object referenced by h_synx
 * and invoke any external binding synx objs.
 * The status parameter will indicate whether the entity
 * performing the signaling wants to convey an error case or a success case.
 *
 * @param session : Session ptr (returned from synx_initialize)
 * @param h_synx  : Synx object handle
 * @param status  : Status of signaling.
 *                  Clients can send custom signaling status
 *                  beyond SYNX_STATE_SIGNALED_MAX.
 *
 * @return Status of operation. Negative in case of error. SYNX_SUCCESS otherwise.
 */
int synx_signal(struct synx_session *session, u32 h_synx,
	enum synx_signal_status status);

/*
 * synx_signal_n – Signals n synx objects
 *
 * Function signals 'h_synx_count' number of synx objects identified by
 * 'h_synx' array parameter. The 'status' array parameter corresponding to
 * 'h_synx' array indicates if the entity performing the signaling wants to
 * convey an error or a success case. 'h_synx_error' array holds per-synx-
 * object error status of signal operation and has -SYNX_ENODATA if the
 * signal operation was not attempted.
 *
 * @param session      : Session ptr (returned from synx_initialize)
 * @param h_synx       : Synx object handle array.
 * @param h_synx_count : Number "n" of synx objects to signal in h_synx
 *                            array.
 * @param status       : Status-of-signaling array for h_synx array.
 *                            - Use NULL if not used.
 * @param h_synx_error : Synx object signal error states for h_synx array.
 *                            - Use NULL if per-synx-object status of operation
 *                              is not needed.
 *                            - A count of error states other than -SYNX_ENODATA
 *                              gives the number of synx objects on which
 *                              signal was attempted.
 *
 * @return Status of operation. Negative in case of error. SYNX_SUCCESS otherwise.
 */
int synx_signal_n(struct synx_session *session, u32 *h_synx, u32 h_synx_count,
	enum synx_signal_status *status, int *h_synx_error);

/**
 * synx_merge - Merges multiple synx objects
 *
 * This function will merge multiple synx objects into a synx group.
 *
 * @param session : Session ptr (returned from synx_initialize)
 * @param params  : Merge params
 *
 * @return Status of operation. Negative in case of error. SYNX_SUCCESS otherwise.
 */
int synx_merge(struct synx_session *session, struct synx_merge_params *params);

/**
 * synx_wait - Waits for a synx object synchronously
 *
 * Does a wait on the synx object identified by h_synx for a maximum
 * of timeout_ms milliseconds. Must not be called from interrupt context as
 * this API can sleep.
 * Will return status if handle was signaled. Status can be from pre-defined
 * states (enum synx_signal_status) or custom status sent by producer.
 *
 * @param session    : Session ptr (returned from synx_initialize)
 * @param h_synx     : Synx object handle to be waited upon
 * @param timeout_ms : Timeout in ms
 *
 * @return Signal status. -SYNX_INVAL if synx object is in bad state or arguments
 * are invalid, -SYNX_TIMEOUT if wait times out.
 */
int synx_wait(struct synx_session *session, u32 h_synx, u64 timeout_ms);

/*
 * synx_read_n - Reads n synx objects
 *
 * Function reads 'h_synx_count' number of synx objects identified by
 * 'h_synx' array parameter with a maximum per-read timeout of 'timeout_ms'
 * milliseconds. The 'status' array parameter corresponding to 'h_synx' array
 * returns statuses if handles were signaled. Status can be from pre-defined
 * states (enum synx_signal_status) or custom status sent by producer.
 * 'h_synx_error' array holds per-synx-object error status of read operation
 * and has -SYNX_ENODATA if the read operation was not attempted.
 *
 * @param session      : Session ptr (returned from synx_initialize)
 * @param h_synx       : Synx object handle array to be read.
 * @param h_synx_count : Number "n" of synx objects to read in h_synx array.
 * @param status       : Signal status of handles in h_synx array.
 *                            - Use NULL if not used.
 * @param h_synx_error : Synx object read error states for h_synx array.
 *                            - Use NULL if per-synx-object status of operation
 *                              is not needed.
 *                            - A count of error states other than -SYNX_ENODATA
 *                              gives the number of synx objects on which read
 *                              was attempted.
 * @param timeout_ms   : Timeout for each object read in ms.
 *                            - Use timeout_ms = 0 for non-blocking read.
 *                            - Use timeout_ms = UINT64_MAX to block and read
 *                              without timeout.
 *
 * @return Status of operation. Negative in case of error. SYNX_SUCCESS otherwise.
 */
int synx_read_n(struct synx_session *session, u32 *h_synx, u32 h_synx_count,
	enum synx_signal_status *status, int *h_synx_error, u64 timeout_ms);

/**
 * synx_get_status - Returns the status of the synx object
 *
 * @param session : Session ptr (returned from synx_initialize)
 * @param h_synx  : Synx object handle
 *
 * @return Status of the synx object.
 */
int synx_get_status(struct synx_session *session, u32 h_synx);

/**
 * synx_import - Imports (looks up) synx object from given handle/fence
 *
 * Import subscribes the client session for notification on signal
 * of handles/fences.
 *
 * @param session : Session ptr (returned from synx_initialize)
 * @param params  : Pointer to import params
 *
 * @return SYNX_SUCCESS upon success, -SYNX_INVAL if synx object is bad state
 */
int synx_import(struct synx_session *session, struct synx_import_params *params);

/**
 * synx_get_fence - Get the native fence backing the synx object
 *
 * Function returns the native fence. Clients need to
 * acquire & release additional reference explicitly.
 *
 * @param session : Session ptr (returned from synx_initialize)
 * @param h_synx  : Synx object handle
 *
 * @return Fence pointer upon success, NULL or error in case of failure.
 */
void *synx_get_fence(struct synx_session *session, u32 h_synx);

/**
 * synx_release - Release the synx object
 *
 * Decrements refcount of a synx object by 1, and destroys it
 * if becomes 0.
 *
 * @param session : Session ptr (returned from synx_initialize)
 * @param h_synx  : Synx object handle to be destroyed
 *
 * @return Status of operation. Negative in case of error. SYNX_SUCCESS otherwise.
 */
int synx_release(struct synx_session *session, u32 h_synx);

/**
 * synx_recover - Recover any possible handle leaks
 *
 * Function should be called on HW hang/reset to
 * recover the Synx handles shared. This cleans up
 * Synx handles held by the rest HW, and avoids
 * potential resource leaks.
 *
 * Function does not destroy the session, but only
 * recover synx handles belonging to the session.
 * Synx session would still be active and clients
 * need to destroy the session explicitly through
 * synx_uninitialize API.
 *
 * @param id : Client ID of core to recover
 *
 * @return Status of operation. Negative in case of error. SYNX_SUCCESS otherwise.
 */
int synx_recover(enum synx_client_id id);

#endif /* __SYNX_API_H__ */
