/*
 ============================================================================
 Name        : ElfParser.c
 Author      : loulei
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>
#include <string.h>

#define FILE_NAME "libtarget.so"

char *freadStr(char *buffer, int n, FILE *fp){
	register int c;
	register char *cs;
	cs = buffer;
	while(--n>0 && (c=getc(fp)) != 0){
		*cs++ = c;
	}
	*cs = '\0';
	return buffer;
}

void readElf(){
	FILE *fp = fopen("file/libdemo.so", "rb");
		if(!fp){
			printf("fopen fail\n");
			return;
		}
		fseek(fp, 0, SEEK_END);
		long fileLen = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		printf("file len:%ld\n", fileLen);

		Elf32_Ehdr ehdr;
		int i;
		Elf32_Shdr shdr;
		Elf32_Sym sym;
		Elf32_Phdr phdr;
		char *type_name = "unknown";
		char **strTab;
		char **dynstrTab;
		char *symtab_data;
		int symtab_data_len;

		fread(&ehdr, 1, sizeof(Elf32_Ehdr), fp);
		printf("e_entry=0x%x\n", ehdr.e_entry);
		printf("e_phoff=%d\n", ehdr.e_phoff);
		printf("e_shoff=%d\n", ehdr.e_shoff);
		printf("e_ehsize=%d\n", ehdr.e_ehsize);
		printf("e_phentsize=%d\n", ehdr.e_phentsize);
		printf("e_phnum=%d\n", ehdr.e_phnum);
		printf("e_shentsize=%d\n", ehdr.e_shentsize);
		printf("e_shnum=%d\n", ehdr.e_shnum);
		printf("e_shstrndx=%d\n", ehdr.e_shstrndx);

		//parse strtab
		fseek(fp, ehdr.e_shoff+ehdr.e_shstrndx*ehdr.e_shentsize, SEEK_SET);
		fread(&shdr, 1, sizeof(Elf32_Shdr), fp);
		if(shdr.sh_type == 3){
			printf("\n---- section name string table ----\n");
			printf("sh_name:%d\n", shdr.sh_name);
			printf("sh_type:%d\n", shdr.sh_type);
			printf("sh_offset:%d\n", shdr.sh_offset);
			printf("sh_size:%d\n", shdr.sh_size);
			printf("sh_addr:0x%x\n", shdr.sh_addr);


			char buffer[4096];
			fseek(fp, shdr.sh_offset, SEEK_SET);
			int totalsize = shdr.sh_size;
			strTab = (char**)calloc(totalsize, sizeof(char*));
			printf("strTab:%ld\n", strTab);
			int readsize = 0;
			printf("   ---- str tab start ----\n");
			while(readsize < totalsize){
				freadStr(buffer, 4096, fp);
				int nameLen = strlen(buffer);
				char *name = (char*)calloc(nameLen+1, sizeof(char));
				memcpy(name, buffer, nameLen);
				printf("index=%d, str=%s\n", readsize, buffer);
				char **tmp = (strTab + readsize);
				*tmp = name;
				readsize+=(strlen(buffer)+1);
			}
			printf("\n   ---- str tab end ----\n");
		}

		Elf32_Shdr relplt_shdr;
		Elf32_Shdr dynsym_shdr;
		Elf32_Shdr dynstr_shdr;
		Elf32_Shdr got_shdr;
		Elf32_Shdr hash_shdr;

		fseek(fp, ehdr.e_shoff, SEEK_SET);
		for(i=0; i<ehdr.e_shnum; i++){
			fread(&shdr, 1, sizeof(Elf32_Shdr), fp);
			printf("------------------  section %d start ------------------\n", i+1);
			char *sh_name = *(strTab+shdr.sh_name);
			printf("sh_index=%d, sh_name=%s\n", shdr.sh_name, sh_name);
			if(shdr.sh_type == 0){
				type_name = "SHT_NULL";
			}else if(shdr.sh_type == 1){
				type_name = "SHT_PROGBITS";
			}else if(shdr.sh_type == 2){
				type_name = "SHT_SYMTAB";
			}else if(shdr.sh_type == 3){
				type_name = "SHT_STRTAB";
			}else if(shdr.sh_type == 4){
				type_name = "SHT_RELA";
			}else if(shdr.sh_type == 5){
				type_name = "SHT_HASH";
			}else if(shdr.sh_type == 6){
				type_name = "SHT_DYNAMIC";
			}else if(shdr.sh_type == 7){
				type_name = "SHT_NOTE";
			}else if(shdr.sh_type == 8){
				type_name = "SHT_NOBITS";
			}else if(shdr.sh_type == 9){
				type_name = "SHT_REL";
			}else if(shdr.sh_type == 10){
				type_name = "SHT_SHLIB";
			}else if(shdr.sh_type == 11){
				type_name = "SHT_DYNSYM";
			}else{
				type_name = "unkonwn";
			}

			if(!strcmp(type_name, ".dynsym")){
				memcpy(&dynsym_shdr, &shdr, sizeof(Elf32_Shdr));
			}else if(!strcmp(type_name, ".dynstr")){
				memcpy(&dynstr_shdr, &shdr, sizeof(Elf32_Shdr));
			}else if(!strcmp(type_name, ".got")){
				memcpy(&got_shdr, &shdr, sizeof(Elf32_Shdr));
			}else if(!strcmp(type_name, ".rel.plt")){
				memcpy(&relplt_shdr, &shdr, sizeof(Elf32_Shdr));
			}else if(!strcmp(type_name, "SHT_HASH")){
				memcpy(&hash_shdr, &shdr, sizeof(Elf32_Shdr));
			}
			printf("sh_type=%d, name=%s\n", shdr.sh_type, type_name);
			printf("sh_flags=%d\n", shdr.sh_flags);
			printf("sh_addr=%d\n", shdr.sh_addr);
			printf("sh_offset=%d\n", shdr.sh_offset);
			printf("sh_size=%d\n", shdr.sh_size);
			printf("sh_link=%d\n", shdr.sh_link);
			printf("sh_entsize=%d\n", shdr.sh_entsize);
			printf("------------------  section %d end ------------------\n\n\n", i+1);
			if(shdr.sh_type == 11){
				long index = ftell(fp);

				fseek(fp, shdr.sh_offset, SEEK_SET);
				symtab_data_len = shdr.sh_size;
				symtab_data = (char*)calloc(sizeof(char), shdr.sh_size);
				fread(symtab_data, sizeof(char), shdr.sh_size, fp);

				fseek(fp, index, SEEK_SET);
			}

			if(sh_name && !strcmp(".dynstr", sh_name)){
				printf("find .dynstr !!!\n");
				dynstrTab = (char**)calloc(shdr.sh_size, sizeof(char*));

				int index = ftell(fp);

				fseek(fp, shdr.sh_offset, SEEK_SET);
				int readsize = 0;
				char buffer[4096];
				while(readsize < shdr.sh_size){
					freadStr(buffer, 4096, fp);
					int nameLen = strlen(buffer);
					char *name = (char*)calloc(nameLen+1, sizeof(char));
					memcpy(name, buffer, nameLen);
					printf("index=%d, str=%s\n", readsize, buffer);
					char **tmp = (dynstrTab + readsize);
					*tmp = name;
					readsize+=(strlen(buffer)+1);
				}

				fseek(fp, index, SEEK_SET);
			}

		}

		printf("symtab len:%d\n", symtab_data_len);
		for(i=0; i<symtab_data_len; i+=sizeof(Elf32_Sym)){
			memcpy(&sym, symtab_data+i, sizeof(Elf32_Sym));
			printf("---------------- symtab %d start -----------------\n", i/sizeof(Elf32_Sym));
			char *st_name = *(dynstrTab+sym.st_name);
			printf("st_index:%d, st_name:%s\n", sym.st_name, st_name);
			// 在可执行文件或者动态库中，符号的值表示的是运行时的内存地址。
			printf("st_value:%d, 0x%x\n", sym.st_value, sym.st_value);
			printf("st_size:%d\n", sym.st_size);
			printf("st_info:%d\n", sym.st_info & 0xff);
			char st_bind = (sym.st_info >> 4) & 0xff;
			char *bindname = "unknown bind";
			if(st_bind == 0){
				bindname = "STB_LOCAL";
			}else if(st_bind == 1){
				bindname = "STB_GLOBAL";
			}else if(st_bind == 2){
				bindname = "STB_WEAK";
			}else if(st_bind == 13 || st_bind == 15){
				bindname = "STB_LOPROC";
			}
			printf("st_bind:%d, bindname:%s\n", st_bind, bindname);
			char st_type = sym.st_info & 0x0f;
			char *typename = "unknown type";
			if(st_type == 0){
				typename = "STT_NOTYPE";
			}else if(st_type == 1){
				typename = "STT_OBJECT";
			}else if(st_type == 2){
				typename = "STT_FUNC";
			}else if(st_type == 3){
				typename = "STT_SECTION";
			}else if(st_type == 4){
				typename = "STT_FILE";
			}else if(st_type == 13){
				typename = "STT_LOPROC";
			}else if(st_type == 15){
				typename = "STT_HIPROC";
			}
			printf("st_type:%d, type name:%s\n", st_type, typename);
			printf("st_shndx:%d\n", sym.st_shndx);
			printf("---------------- symtab %d end -----------------\n\n", i/sizeof(Elf32_Sym));
		}

		printf("=====================================  parse program segments ================================\n\n");
		fseek(fp, ehdr.e_phoff, SEEK_SET);
		for(i=0; i<ehdr.e_phnum; i++){
			fread(&phdr, 1, sizeof(Elf32_Phdr), fp);
			printf("----------------- segment %d start ----------------------\n", i);
			char *typename = "unknown type";
			if(phdr.p_type == 0){
				typename = "PT_NULL";
			}else if(phdr.p_type == 1){
				typename = "PT_LOAD";
			}else if(phdr.p_type == 2){
				typename = "PT_DYNAMIC";
			}else if(phdr.p_type == 3){
				typename = "PT_INTERP";
			}else if(phdr.p_type == 4){
				typename = "PT_NOTE";
			}else if(phdr.p_type == 5){
				typename = "PT_SHLIB";
			}else if(phdr.p_type == 6){
				typename = "PT_PHDR";
			}
			printf("p_type=%d, name=%s\n", phdr.p_type, typename);
			printf("p_offset=%d\n", phdr.p_offset);
			printf("p_vaddr=0x%x\n", phdr.p_vaddr);
			printf("p_paddr=0x%x\n", phdr.p_paddr);
			printf("p_filesz=%d\n", phdr.p_filesz);
			printf("p_memsz=%d\n", phdr.p_memsz);
			printf("p_flags=%d\n", phdr.p_flags);
			printf("p_align=%d\n", phdr.p_align);
			printf("----------------- segment %d end ----------------------\n", i);
		}


		printf("\n\n--------------- parse hash ------------------\n");

		uint32_t hashOffset = 0;
		int hashTblNum = 0;

		int32_t nbuckets;
		int32_t nchains;

		uint32_t *buckets;
		uint32_t *chains;

		printf("sh_size:%d, sh_entsize:%d\n", hash_shdr.sh_size, hash_shdr.sh_entsize);

		hashOffset = hash_shdr.sh_offset;
		hashTblNum = hash_shdr.sh_size/hash_shdr.sh_entsize;

		printf("hash offset:0x%04X, hash num:%d\n", hashOffset, hashTblNum);

		fseek(fp, hashOffset, SEEK_SET);

		fread(&nbuckets, 1, sizeof(nbuckets), fp);
		fread(&nchains, 1, sizeof(nchains), fp);

		printf("bucket num:%d, chain num:%d\n", nbuckets, nchains);

		buckets = (uint32_t*)malloc(nbuckets*sizeof(uint32_t));
		chains = (uint32_t*)malloc(nchains*sizeof(uint32_t));

		for(i=0; i<nbuckets; i++){
			fread(buckets+i, 1, sizeof(uint32_t), fp);
			printf("bucket %d:%d\n", i, buckets[i]);
		}

		for(i=0; i<nchains; i++){
			fread(chains+i, 1, sizeof(uint32_t), fp);
			printf("chain %d:%d\n", i, chains[i]);
		}

		uint32_t actual = nbuckets * 4 + nchains * 4 + 8;

		printf("actual len:%d\n", actual);

		free(strTab);
		free(dynstrTab);
		free(symtab_data);
		fclose(fp);
}

void printSymble() {
	FILE* fp = fopen("file/libtarget.so", "rb");
	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);
	printf("file %s len: %ld\n", FILE_NAME, size);
	fseek(fp, 0, SEEK_SET);
	Elf32_Ehdr ehdr;
	Elf32_Shdr shstr;
	char* shstrtab;
	Elf32_Shdr shdr;
	int i = 0;
	char* str;
	Elf32_Shdr relplt_shdr;
	Elf32_Shdr dynsym_shdr;
	Elf32_Shdr dynstr_shdr;
	Elf32_Shdr got_shdr;
	char* dynstr;
	Elf32_Sym* dynsymtab;
	Elf32_Rel* rel_ent;
	uint32_t offset = 0;
	fread(&ehdr, sizeof(Elf32_Ehdr), 1, fp);
	uint32_t shdr_base = ehdr.e_shoff;
	uint16_t shnum = ehdr.e_shnum;
	uint32_t shstr_base = shdr_base + ehdr.e_shstrndx * sizeof(Elf32_Shdr);
	printf("section number:%d\n", shnum);
	printf("section base:%d\n", shdr_base);
	printf("strtab section base : %d\n", shstr_base);
	fseek(fp, shstr_base, SEEK_SET);
	fread(&shstr, sizeof(Elf32_Shdr), 1, fp);
	printf("string tab size:%d\n", shstr.sh_size);
	shstrtab = (char*) malloc(shstr.sh_size);
	fseek(fp, shstr.sh_offset, SEEK_SET);
	fread(shstrtab, shstr.sh_size, 1, fp);
	fseek(fp, shdr_base, SEEK_SET);
	for (i = 0; i < shnum; i++) {
		fread(&shdr, sizeof(Elf32_Shdr), 1, fp);
		str = shstrtab + shdr.sh_name;
		printf("section name:%s\n", str);
		if (!strcmp(str, ".dynsym")) {
			memcpy(&dynsym_shdr, &shdr, sizeof(Elf32_Shdr));
		} else if (!strcmp(str, ".dynstr")) {
			memcpy(&dynstr_shdr, &shdr, sizeof(Elf32_Shdr));
		} else if (!strcmp(str, ".rel.plt")) {
			memcpy(&relplt_shdr, &shdr, sizeof(Elf32_Shdr));
		} else if (!strcmp(str, ".got")) {
			memcpy(&got_shdr, &shdr, sizeof(Elf32_Shdr));
		}
	}
	dynstr = (char*) malloc(dynstr_shdr.sh_size);
	fseek(fp, dynstr_shdr.sh_offset, SEEK_SET);
	fread(dynstr, dynstr_shdr.sh_size, 1, fp);
	dynsymtab = (Elf32_Sym*) malloc(dynsym_shdr.sh_size);
	//	printf("dynsym size:%d\n", dynsym_shdr.sh_size);
	fseek(fp, dynsym_shdr.sh_offset, SEEK_SET);
	fread(dynsymtab, dynsym_shdr.sh_size, 1, fp);
	rel_ent = (Elf32_Rel*) malloc(sizeof(Elf32_Rel));
	fseek(fp, relplt_shdr.sh_offset, SEEK_SET);
	fread(rel_ent, sizeof(Elf32_Rel), 1, fp);
	for (i = 0; i < relplt_shdr.sh_size / sizeof(Elf32_Rel); i++) {
		uint16_t ndx = ELF32_R_SYM(rel_ent->r_info);
		printf("symstr:%s offset:%d\n", dynstr + dynsymtab[ndx].st_name,
				rel_ent->r_offset);
		fread(rel_ent, sizeof(Elf32_Rel), 1, fp);
	}
	printf(
			"============================================================================================\n");
	for (i = 0; i < (dynsym_shdr.sh_size) / sizeof(Elf32_Sym); i++) {
		printf("symstr:%s offset:%d\n", dynstr + dynsymtab[i].st_name,
				dynsymtab[i].st_value);
	}
	free(dynsymtab);
	free(rel_ent);
	free(shstrtab);
	fclose(fp);
}

uint32_t getLibAddress(const char *name){
	unsigned long ret = 0;
	char buf[4096], *temp;
	int pid;
	FILE *fp;

	pid = getpid();
	sprintf(buf, "/proc/%d/maps", pid);
	printf("pid=%d\n", pid);
	fp = fopen(buf, "r");
	while(fgets(buf, sizeof(buf), fp)){
		printf("%s\n", buf);
	}

	fclose(fp);
	return ret;
}

int main(void) {
	readElf();
//	printSymble();
//	getLibAddress("");
	return EXIT_SUCCESS;
}

//------------------  section 2 start ------------------
//sh_index=11, sh_name=.dynsym
//sh_type=11, name=SHT_DYNSYM
//sh_flags=2
//sh_addr=276
//sh_offset=276
//sh_size=1216
//sh_link=2
//sh_entsize=16
//------------------  section 2 end ------------------

/*
1) .text section 里装载了可执行代码；

2) .data section 里面装载了被初始化的数据；

3) .bss section 里面装载了未被初始化的数据；

4) 以 .rec 打头的 sections 里面装载了重定位条目；

5) .symtab 或者 .dynsym section 里面装载了符号信息；

6) .strtab 或者 .dynstr section 里面装载了字符串信息；

7) 其他还有为满足不同目的所设置的section，比方满足调试的目的、满足动态链接与加载的目的等等。
*/
