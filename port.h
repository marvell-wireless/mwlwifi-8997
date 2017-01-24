
/******************************************************
Change log:
    11/07/2008: initial version
******************************************************/

#ifndef _MLAN_DECL_H_
#define _MLAN_DECL_H_ 

/** MLAN release version */
#define MLAN_RELEASE_VERSION		 "C204"

/** Re-define generic data types for MLAN/MOAL */
/** Signed char (1-byte) */
typedef    signed char           t_s8;
/** Unsigned char (1-byte) */
typedef    unsigned char         t_u8;
/** Signed short (2-bytes) */
typedef    short                 t_s16;
/** Unsigned short (2-bytes) */
typedef    unsigned short        t_u16;
/** Signed long (4-bytes) */
typedef    int                   t_s32;
/** Unsigned long (4-bytes) */
typedef    unsigned int          t_u32;
/** Signed long long 8-bytes) */
typedef    long long             t_s64;
/** Unsigned long long 8-bytes) */
typedef    unsigned long long    t_u64;
/** Void pointer (4-bytes) */
typedef    void                  t_void;
/** Size type */
typedef	   t_u32                 t_size;
/** Boolean type */
typedef    t_u8                  t_bool;

#ifdef MLAN_64BIT
/** Pointer type (64-bit) */
typedef    t_u64                 t_ptr;
/** Signed value (64-bit) */
typedef    t_s64                 t_sval;
#else
/** Pointer type (32-bit) */
typedef    t_u32                 t_ptr;
/** Signed value (32-bit) */
typedef    t_s32                 t_sval;
#endif

/** Constants below */

#ifdef __GNUC__
/** Structure packing begins */
#define MLAN_PACK_START
/** Structure packeing end */
#define MLAN_PACK_END  __attribute__((packed))
#else /* !__GNUC__ */
#ifdef PRAGMA_PACK
/** Structure packing begins */
#define MLAN_PACK_START
/** Structure packeing end */
#define MLAN_PACK_END
#else /* !PRAGMA_PACK */
/** Structure packing begins */
#define MLAN_PACK_START   __packed
/** Structure packing end */
#define MLAN_PACK_END
#endif /* PRAGMA_PACK */
#endif /* __GNUC__ */

#ifndef INLINE
#ifdef __GNUC__
/** inline directive */
#define	INLINE	inline
#else
/** inline directive */
#define	INLINE	__inline
#endif
#endif

#define MNULL NULL
#define MLAN_STATUS_FAILURE (-1)
#define MLAN_STATUS_SUCCESS (0)

/** MLAN TRUE */
#define MTRUE                    (1)
/** MLAN FALSE */
#define MFALSE                   (0)

/** BIT value */
#define MBIT(x)    (((t_u32)1) << (x))


#endif
