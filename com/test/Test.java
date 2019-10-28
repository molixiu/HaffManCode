package com.test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Scanner;

import com.xjwfk.utils.HaffManUtils;

public class Test {
	public static void main(String[] args) throws IOException {
		RandomAccessFile bis = new RandomAccessFile("C:\\new\\1.zip","r");
		FileOutputStream out = new FileOutputStream("C:\\new\\jiami.zip");
		ArrayList<HaffManUtils.HFCode<Byte,Byte>> secretKeyList = HaffManUtils.encryptFile(bis, out);
		
		bis.close();
		out.close();
		
		FileInputStream in = new FileInputStream("C:\\new\\jiami.zip");
		FileOutputStream out1 = new FileOutputStream("C:\\new\\jiemi.zip");
		
		HaffManUtils.decryptFile(in, out1, secretKeyList);
		in.close();
		out1.close();
		System.out.println("完成");
		System.out.println((byte)0xC0);
    }		
}
