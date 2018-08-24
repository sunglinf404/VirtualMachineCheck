#define _GetVwareFileStuct_
#ifdef  _GetVwareFileStuct_

#pragma pack(1)

#define  SECTOR_SIZE 512
#define  FILE_SECTOR_SIZE 1024

typedef struct _MBR_Heads
{
	UCHAR   _MBR_Boot_Indication;
	UCHAR   _MBR_Start_Head;
	UCHAR   _MBR_Start_SectorAndCylin[2];
	UCHAR   _MBR_Partition_Type;
	UCHAR   _MBR_End_Head;
	UCHAR   _MBR_End_SectorAndCylin[2];
	DWORD   _MBR_Sec_pre_pa;
	DWORD   _Sections_in_Patition;
}MBR_Heads, *LMBR_Heads;

typedef struct _GPT_Heads
{
	DWORD64 _Singed_name;
	DWORD   _BanBen;
	DWORD   _Crc;
	DWORD   _Reserves;
	DWORD64 _GPT_At_SQ;
	DWORD64 _GPTB_At_SQ;
	DWORD64 _GPT_Start_SQ;
	DWORD64 _GPT_End_SQ;
	DWORD64 _GUID_CIPAN[2];
	DWORD64 _GPT_FB_Start_SQ;
	DWORD   _GPT_FB_Num;
	DWORD   _GPT_FB_BYTE;
	DWORD   _GPT_FB_CRC;
}GPT_Heads, *LGPT_Heads;
typedef struct _GPT_FB_TABLE
{
	DWORD64 _GUID_TYPE[2];
	DWORD64 _GUID_FB[2];
	DWORD64 _FB_Start_SQ;
	DWORD64 _FB_End_SQ;
	DWORD64 _FB_Attribute;
	UCHAR   _FB_NAME[72];
}GPT_FB_TABLE, *LGPT_FB_TABLE;

typedef struct _NTFS_TABLES
{
	UCHAR   _T_Commond[3];
	UCHAR   _OEM_ID[8];
	UCHAR    _Single_SQ_Bytes[2];
	UCHAR   _Single_Cu_Num;
	UCHAR    _Reserve_SQ[2];
	UCHAR   _Nulls[3];
	UCHAR    _Not_Use[2];
	UCHAR   _J_Discrible;
	UCHAR    _Always_Zero[2];
	UCHAR    _Ever_CHS_Num[2];
	UCHAR    _CHS_TNum[2];
	DWORD   _YZ_SQ_Num;
	DWORD   _NTFS_Not_USE;
	DWORD   _NTFS_Not_USE2;
	DWORD64 _NTFS_SQ_TNum;
	DWORD64 _MFT_Start_CU;
	DWORD64 _MFTMirr_Start_CU;
	CHAR    _NTFS_File_Recoding;
	UCHAR   _NTFS_Not_USE3[3];
	CHAR    _NTFS_Buffer_Index;
	UCHAR   _NTFS_Not_USE4[3];
	DWORD64 _NTFS_Volume_Index;
	DWORD   _NTFS_CRC;
}NTFS_TABLES, *LNTFS_TABLES;

typedef struct _FILE_Head_Recoding
{
	DWORD   _FILE_Index;
	UCHAR   _Update_Sequence_Number[2];
	UCHAR   _Update_Size[2];
	DWORD64 _LogFile_Sequence_Number;
	UCHAR   _Sequence_Number[2];
	UCHAR   _Hard_Link_Count[2];
	UCHAR   _First_Attribute_Dev[2];
	UCHAR   _Flags[2];
	DWORD   _File_Recod_TLength;
	DWORD   _File_Recod_DLength;
	DWORD64 _FR_File_Index;
	UCHAR   _Next_Attribute_ID[2];
	UCHAR   _Boundry[2];
	DWORD   _FR_Refer;
	UCHAR   _Update_Serial_Num[2];
	UCHAR   _Update_array[4];
	UCHAR   _Not_Use[2];
}FILE_Head_Recoding, *LFILE_Head_Recoding;

typedef struct _PAttribute_Head
{
	DWORD   _PN_AttrBody_Length;
	UCHAR   _PN_AttrBody_Start_Offset[2];
	UCHAR   _PN_Index_Sign;
	UCHAR   _PN_Not_Use;
}PAttribute_Head, *LPAttribute_Head;

typedef struct _NPAttribute_Head
{
	DWORD64 _NPN_Attr_Start_VCN;
	DWORD64 _NPN_Attr_End_VCN;
	UCHAR   _NPN_RunList_Offset[2];
	UCHAR   _NPN_Compress_Size[2];
	DWORD   _NPN_Not_Use;
	DWORD64 _NPN_Attr_F_Size;
	DWORD64 _NPN_Attr_T_Size;
	DWORD64 _NPN_Attr_Init_Size;
}NPAttribute_Head, *LNPAttribute_Head;

typedef struct _ATTRIBUTE_HEADS
{
	DWORD   _Attr_Type;
	DWORD   _Attr_Length;
	UCHAR   _PP_Attr;
	UCHAR   _AttrName_Length;
	UCHAR   _AttrName_Start_Offset[2];
	UCHAR   _S_Sign[2];
	UCHAR   _Attr_ID[2];
	union{
		PAttribute_Head  P_head;
		NPAttribute_Head NP_head;
	}TWOATTRIBUTEHEAD;
}ATTRIBUTE_HEADS, *LATTRIBUTE_HEADS;

typedef struct _Attr_10H
{
	DWORD64 _H10_FILE_Built_TM;
	DWORD64 _H10_FILE_Revise_LTM;
	DWORD64 _H10_MFT_Revise_TM;
	DWORD64 _H10_FILE_Visit_LTM;
	DWORD   _H10_Tridition_FILE_Attr;
	DWORD   _H10_MAX_Edit_Num;
	DWORD   _H10_Edit_Num;
	DWORD   _H10_TwoWay_ID;
	DWORD   _H10_Owner_ID;
	DWORD   _H10_Safe_ID;
	DWORD64 _H10_Quota_Manage;
	DWORD64 _H10_Update_USN;
}Attr_10H, *LAttr_10H;

typedef struct _Attr_20H
{
	DWORD   _H20_TYPE;
	UCHAR   _H20_Recod_Length[2];
	UCHAR   _H20_Attr_Name_Length;
	UCHAR   _H20_Attr_Name_Offset;
	DWORD64 _H20_Start_VCN;
	LARGE_INTEGER _H20_FILE_Reference_Num;
	UCHAR   _H20_Attr_ID[2];
}Attr_20H, *LAttr_20H;

typedef struct _Attr_30H
{
	UCHAR   _H30_Parent_FILE_Reference[8];
	DWORD64 _H30_FILE_Built_TM;
	DWORD64 _H30_FILE_Recise_TM;
	DWORD64 _H30_MFT_Recise_TM;
	DWORD64 _H30_FILE_Visit_LTM;
	DWORD64 _H30_FILE_Distribu_Size;
	DWORD64 _H30_FILE_TSize;
	DWORD   _H30_Flag;
	DWORD   _H30_EAs_Reparse;
	UCHAR   _H30_FILE_Name_Length;
	UCHAR   _H30_FILE_Name_Spase;
}Attr_30H, *LAttr_30H;

typedef struct _Attr_40H
{
	DWORD64 _H40_GUID_Object_ID[2];
	DWORD64 _H40_GUID_Birth_Volume_ID[2];
	DWORD64 _H40_GUID_Birth_Object_ID[2];
	DWORD64 _H40_GUID_Domain_ID[2];
}Attr_40H, *LAttr_40H;

typedef struct _Attr_70H
{
	DWORD64 _H70_ZOR;
	UCHAR   _H70_Main_Edition;
	UCHAR   _H70_Second_Editon;
	UCHAR   _H70_Flag[2];
	DWORD   _H70_ZOR_TWO;
}Attr_70H, *LAttr_70H;

typedef struct _Attr_90H_Index_ROOT
{
	DWORD   _H90_IR_Attr_Type;
	DWORD   _H90_IR_Collation;
	DWORD   _H90_IR_Index_Buffer_Size;
	UCHAR   _H90_IR_Index_Buffer_CU_Num;
	UCHAR   _H90_IR_Not_Use[3];
}Attr_90H_Index_ROOT, *LAttr_90H_Index_ROOT;

typedef struct _Attr_90H_Index_Head
{
	DWORD   _H90_IH_Index_Offset;
	DWORD   _H90_IH_Index_Total_Size;
	DWORD   _H90_IH_Index_Dis_Size;
	UCHAR   _H90_IH_Flag;
	UCHAR   _H90_IH_Not_Use[3];
}Attr_90H_Index_Head, *LAttr_90H_Index_Head;

typedef struct _Attr_90H_Index_Entry
{
	UCHAR _H90_IE_MFT_Reference_Index[8];
	UCHAR   _H90_IE_Index_Size[2];
	UCHAR   _H90_IE_FILE_Attr_Name_Size[2];
	UCHAR   _H90_IE_Index_Flag[2];
	UCHAR   _H90_IE_Not_Use[2];
	UCHAR	_H90_IE_Parent_MFT_Refer[8];
	UCHAR	_H90_IE_FILE_Built_TM[8];
	UCHAR	_H90_IE_FILE_Revise_LTM[8];
	UCHAR	_H90_IE_FILE_Recode_Revise_LTM[8];
	UCHAR	_H90_IE_FILE_Visit_LTM[8];
	DWORD64 _H90_IE_FILE_F_Size;
	DWORD64 _H90_IE_FILE_T_Size;
	DWORD64 _H90_IE_FILE_Flag;
	UCHAR   _H90_IE_FILE_Name_Length;
	UCHAR   _H90_IE_FILE_NameSpace;
}Attr_90H_Index_Entry, *LAttr_90H_Index_Entry;

typedef struct _Attr_C0H
{
	DWORD   _HC0_Re_Analysis_Type;
	UCHAR   _HC0_Re_Analysis_DataLength[2];
	UCHAR   _HC0_Not_Use[2];
}Attr_C0H, *LAttr_C0H;

typedef struct _Attr_D0H
{
	UCHAR   _HD0_Extend_Attr_Length[2];
	UCHAR   _HD0_NEED_EA_Num[2];
	DWORD   _HD0_Extend_aTTR_FLength;
}Attr_D0H, *LAttr_D0H;

typedef struct _Attr_E0H
{
	DWORD   _HE0_Next_ExtendAttr_Offset;
	UCHAR   _HE0_Flag;
	UCHAR   _HE0_Name_Length;
	UCHAR   _HE0_Data_Length[2];
}Attr_E0H, *LAttr_E0H;

typedef struct _STANDARD_INDEX_HEAD
{
	DWORD   _Head_Index;
	UCHAR   _Updat_Sequ_Num_Off[2];
	UCHAR   _Updat_Sequ_Num_Off_Size[2];
	DWORD64 _Log_File_Seque;
	DWORD64 _Index_Buffer_VCN;
	DWORD   _Index_Term_Off;
	DWORD   _Index_Term_Size;
	DWORD   _Index_FB_Size;
	UCHAR   _Child_Node_Index;
	UCHAR   _Not_Use_Zo[3];
	UCHAR   _Updat_Sequ_Num[2];

}STANDARD_INDEX_HEAD, *LSTANDARD_INDEX_HEAD;

typedef struct _STANDARD_INDEX_TERMS
{
	UCHAR   _File_MFT_Refer_Num[8];
	UCHAR   _TIndex_Term_Size[2];
	UCHAR   _File_Attr_Size[2];
	UCHAR   _Indexs[2];
	UCHAR   _NU[2];
	UCHAR   _Parent_MFT_RF[8];
	UCHAR   _File_CJ[8];
	DWORD64 _Last_Revise_TM;
	DWORD64 _Last_File_Recode_Revise_TM;
	DWORD64 _Last_FW_TM;
	DWORD64 _File_FB_SIZE;
	UCHAR   _File_T_Size[8];
	DWORD64 _File_Index;
	UCHAR   _FileName_Length;
	UCHAR   _File_Na_Space;
}STANDARD_INDEX_TERMS, *LSTANDARD_INDEX_TERMS;

typedef struct _HIVE_HEAD
{
	DWORD   _Signature;
	DWORD   _Sequence1;
	DWORD   _Sequence2;
	LARGE_INTEGER _TimeStamp;
	DWORD   _Major;
	DWORD   _Minor;
	DWORD   _Type;
	DWORD   _Format;
	DWORD   _RootCell;
	DWORD   _Length;
	DWORD   _Cluster;
	UCHAR   _Name[64];
	DWORD   _Reserve[99];
	DWORD   _CheckSum;
	DWORD   _Reserve2[894];
	DWORD   _BootType;
	DWORD   _BootRecover;
}HIVE_HEAD, *LHIVE_HEAD;

typedef struct _HIVE_HBIN_HEAD
{
	DWORD   _Signature;
	DWORD   _FileOffset;
	DWORD   _SIZE;
	DWORD   _Reserved[2];
	LARGE_INTEGER _TimeStamp;
	DWORD   _Spare;
}HIVE_HBIN_HEAD, *LHIVE_HBIN_HEAD;

typedef struct _HIVE_nk_head
{
	DWORD   _Begin_Rserved;
	UCHAR   _Signature[2];
	UCHAR   _Flags[2];
	LARGE_INTEGER _LastWriteTime;
	DWORD   _Spare;
	DWORD   _Parent;
	DWORD   _SubKeyCounts[2];
	union
	{
		struct
		{
			DWORD _SubKeyLists[2];
			DWORD _Count;
			DWORD _List;
		};
		DWORD  _ChildHiveRefernce[4];
	};
	DWORD   _Security;
	DWORD   _Class;
	DWORD   _MaxNameLen:16;
	DWORD   _UserFlags:4;
	DWORD   _VirtControlFlags:4;
	DWORD   _Debug:8;
	DWORD   _MaxClassLen;
	DWORD   _MaxValueNameLen;
	DWORD   _MaxValueDataLen;
	DWORD   _WorkVar;
	UCHAR   _NameLength[2];
	UCHAR   _ClassLength[2];
}HIVE_nk_head, *LHIVE_nk_head;

typedef struct _HIVE_vk_head
{
	DWORD   _Begin_Rserved;
	UCHAR   _Signature[2];
	UCHAR   _NameLength[2];
	DWORD   _DataLength;
	DWORD   _Data;
	DWORD   _Type;
	UCHAR   _Flags[2];
	UCHAR   _Spare[2];
}HIVE_vk_head, *LHIVE_vk_head;

typedef struct _Virtual_head
{
	DWORD   _Signature;
	DWORD   _Version_num;
	DWORD   _Flag;
	DWORD64 _File_capacity;
	DWORD64 _Grain_size;
	DWORD64 _Description_file_off;
	DWORD64 _Description_file_size;
	DWORD   _Grain_num;
	DWORD64 _Redundant_grain_list_off;
	DWORD64 _Grain_list_off;
	DWORD64 _Metadata_num;
	UCHAR   _Shutdown_flag;
	DWORD   _Extent_check;
	UCHAR   _Compress[2];
}Virtual_head, *LVirtual_head;

typedef struct _Grain_list
{
	DWORD grain_addr[65536];
}Grain_list,*LGrain_list;

typedef struct _VHD_footer
{

	LARGE_INTEGER _MAGIC;
	DWORD   _Features;
	DWORD   _ff_version;
	LARGE_INTEGER _data_offset;
	DWORD   _timestamp;
	DWORD   _crtr_app;
	DWORD   _crtr_ver;
	DWORD   _crtr_os;
	LARGE_INTEGER _orig_size;
	LARGE_INTEGER _curr_size;
	DWORD   _Diskgeometry;
	UCHAR   _Disktype[4];
	DWORD   _checksum;
	LARGE_INTEGER _UUID[2];

}VHD_footer,*LVHD_footer;
typedef struct _VHD_Head
{
	LARGE_INTEGER _MAGIC;
	DWORD64 _Reserve;
	DWORD _Bat_offsetHighPart;
	DWORD _Bat_offsetLowPart;
	//LARGE_INTEGER _Bat_offset;
	DWORD   _hdr_ver;
	UCHAR   _Bat_entry_number[4];
	DWORD   _block_size;
	DWORD   _checksum;
	LARGE_INTEGER _Parent_UUID[2];
	DWORD   _ParentTime;
	DWORD   _Reserve_t;
}VHD_Head,*LVHD_Head;
typedef struct _VDIHead
{
	DWORD _VboxSignature[10];
	UCHAR _VboxReserve[24];
	DWORD _VboxFinalSignature[4];
	UCHAR _VdiReserve[260];
	DWORD _VdiBatSingleSize;
	DWORD _VdiDataStartAddr;
	DWORD _VdiZero[3];
	DWORD _VdiSectorSize;
	DWORD _VdiZero1;
	LARGE_INTEGER _VdiCheckOne;
	DWORD _VdiBatStartAddr;
	DWORD _VdiZero2;
	DWORD _VdiCheckTwo;
	DWORD _EffectiveBatNumber;//有效数据所占BAT表的个数，加上配置数据大小等于有效数据总大小
	LARGE_INTEGER _VdiUUID[4];
	LARGE_INTEGER _VdiParentUUID[4];
	DWORD _VdiUUIDEndSign[4];

}VDIHead,*LVDIHead;
typedef struct _ShortCutHead
{
	DWORD _ShortCutSign;
	UCHAR _ShortCutGUID[16];
	DWORD _ShortCutFlags;
	DWORD _ShortCutAttribute;
	UCHAR _ShortCutCreatTM[8];
	UCHAR _ShortCutModifyTM[8];
	UCHAR _ShortCutLastVistTM[8];
	DWORD _ShortCutFileLength;
	DWORD _ShortCutIconNum;
	DWORD _ShortCutWindowsMode;
	DWORD _ShortCutHotKey;
	DWORD _ShortCutNOuse[2];

}ShortCutHead, *LShortCutHead;
typedef struct _ShortCutLoctionInfo
{
	DWORD _SCLInfoTotalSize;
	DWORD _SCLInfoHeadLength;
	DWORD _SCLInfoFlag;
	DWORD _SCLInfoLocalVolumeOff;
	DWORD _SCLInfoLocalPathOff;
	DWORD _SCLInfoInternetVolumeOff;
	DWORD _SCLInfoAdditionalInfoOff;

}ShortCutLoctionInfo, *LShortCutLoctionInfo;
#endif