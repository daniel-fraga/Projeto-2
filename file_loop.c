// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  minix regular file handling primitives
 */
#define SIZE_OF_DATA 32
#include "minix.h"
#include <linux/fs.h>
#include <linux/uio.h>
#include <asm/uaccess.h>
#include <linux/crypto.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
/*
 * We have mostly NULLs here: the current defaults are OK for
 * the minix filesystem.
 */
 
static char *key;
module_param(key,charp,0000);

//static char *key = "123456789ABCDEF";
static ssize_t readFile (struct kiocb *iocb, struct iov_iter *iter);
static ssize_t writeFile (struct kiocb *iocb, struct iov_iter *from);
static int preRW (int i);

static u8 criptografado[SIZE_OF_DATA / 2];
static u8 descriptografado[SIZE_OF_DATA];
static struct crypto_cipher *cryptoCipher = NULL;

const struct file_operations minix_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= readFile,
	.write_iter	= writeFile,
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
};

static int preRW(int i)
{
	cryptoCipher = crypto_alloc_cipher("aes",0,0);
	
	if(IS_ERR(crypto_cipher_tfm(cryptoCipher))){
		pr_info("cryptodevice: Nao conseguiu alocar handle");
		return PTR_ERR(crypto_cipher_tfm(cryptoCipher));
	}
	if(crypto_cipher_setkey(cryptoCipher,key,32 * sizeof(u8)) != 0){
		pr_info("Não foi possivel definir a chave");
		return 1;
	}
	return 0;
}

//funcao para descriptografar
static ssize_t readFile (struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t ret;
	int i;
	char *ptr = (char*) iter->kvec->iov_base;
	char aux[17];
	printk("Entrou no read");

	ret = generic_file_read_iter(iocb,iter);
	printk("ptr contem:%s", ptr);

	
	preRW(1);
	
	for(i=0;i<strlen(ptr)/16;i++){
	
		memcpy(aux,ptr+16*i,16);
	
		crypto_cipher_decrypt_one(cryptoCipher,descriptografado,aux);
		printk(KERN_INFO "cryptodevice: descriptografado na leitura: %s", descriptografado);
	
		memcpy(ptr+16*i,descriptografado,sizeof(descriptografado));
		
	}
	
	printk("Ptr eh:%s\n", ptr);
	
	
	crypto_free_cipher(cryptoCipher);
	printk("saiu no read");
	return ret;
	
}
//funcao para criptografar
static ssize_t writeFile (struct kiocb *iocb, struct iov_iter *from)
{
	
	ssize_t ret;
	int i;
	char *ptr = (char*) from->kvec->iov_base;
	printk("Entrou no write");
	char aux[17];
	preRW(1);
	printk("PTR antes de criptografar:%s", ptr);
	
	for(i=0;i<strlen(ptr)/16;i++){
	
		memcpy(aux,ptr+16*i,16);	
		
		crypto_cipher_encrypt_one(cryptoCipher,criptografado,aux);
		
		printk(KERN_INFO "cryptodevice: criptografado:");
		for(i=0;i<sizeof(criptografado);i++)
		{
			printk(KERN_CONT "%02hhx", criptografado[i]);
		}

  		memcpy(ptr+16*i,criptografado,sizeof(criptografado));
  		
	}
	
	printk("ptr depois de criptografar:%s", ptr);
	
	ret = generic_file_write_iter(iocb,from);
	
	crypto_free_cipher(cryptoCipher);
	printk("saiu no write");
	return ret;
}

static int minix_setattr(struct dentry *dentry, struct iattr *attr)
{
	
	struct inode *inode = d_inode(dentry);
	int error;

	error = setattr_prepare(dentry, attr);
	if (error)
		return error;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;

		truncate_setsize(inode, attr->ia_size);
		minix_truncate(inode);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

const struct inode_operations minix_file_inode_operations = {
	.setattr	= minix_setattr,
	.getattr	= minix_getattr,
};
