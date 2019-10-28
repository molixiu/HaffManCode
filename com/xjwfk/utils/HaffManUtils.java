package com.xjwfk.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;

/*这个工具类通过哈夫曼算法计算出一个密钥可以对文件进行加密或者解密*/
public class HaffManUtils {
	
	/*O和A分别代表原始数据和编码加密后的数据，知道HFCode可以进行加密或者解密*/
	public static class HFCode<O,A> {
		final O original_Code;	//原始数据
		final A after_Code;		//编码加密后的数据
		
		HFCode(O original_Code, A after_Code) {
			this.original_Code = original_Code;
			this.after_Code = after_Code;
		}

		O getOriginal_Code() { return original_Code; }

		A getAfter_Code() {return after_Code;}
	}
	
	/*用于构建哈夫曼树的链表的节点*/
	static public class HFlistNode {
		HFtreeNode hfNode;
		int weight;
		
		/*比较器 可以得出集合中最小的元素*/
		static final Comparator<HFlistNode> comparatorMin = new Comparator<HFlistNode>() {
			@Override
			public int compare(HFlistNode node1, HFlistNode node2) {
				return node1.getWeight() - node2.getWeight();
			}
		};
		
		HFlistNode(HFtreeNode hfNode, int weight) {
			this.hfNode = hfNode;
			this.weight = weight;
		}
		
		HFtreeNode getHfNode() { return hfNode; }
		
		void setHfNode(HFtreeNode hfNode) { this.hfNode = hfNode; }
		
		int getWeight() { return weight; }
		
		void setWeight(int weight) { this.weight = weight; }
	}

	/*哈夫曼树的节点*/
	static class HFtreeNode {
		Byte symbol;	//节点的值
		HFtreeNode left;	//左子树
		HFtreeNode right;	//右子树
		
		public HFtreeNode(Byte symbol,HFtreeNode left, HFtreeNode right) {
			this.symbol = symbol;
			this.left = left;
			this.right = right;
		}
		
		HFtreeNode(Byte symbol) { this(symbol, null, null); }
		
		HFtreeNode(HFtreeNode left, HFtreeNode right) { this(null, left, right); }
		
		byte getSymbol() { return symbol; }
		
		void setSymbol(Byte symbol) { this.symbol = symbol; }
		
		HFtreeNode getLeft() { return left; }
		
		void setLeft(HFtreeNode left) { this.left = left; }
		
		HFtreeNode getRight() { return right; }
		
		void setRight(HFtreeNode right) { this.right = right; }
	}


	/*加密文件并把密钥返回
	 * @param in 要加密的文件的输入流
	 * @param out 文件加密后的输出流
	 * return 数组类型的密钥
	 * */
	public static ArrayList<HFCode<Byte,Byte>> encryptFile(RandomAccessFile in, OutputStream out) throws IOException {
		HaffManModule haffManModule= new HaffManModule();
		ArrayList<HFCode<Byte,Byte>> secretKeyList = haffManModule.secretKeyList(in);	//密钥
		in.seek(0);//把文件指针移到文件头
		byte[] buffer_read = new byte[1024 * 8];	//读的缓冲区
		byte[] buffer_write = new byte[1024 * 8];	//写的缓冲区
		int len = 0;
		while( (len = in.read(buffer_read)) != -1 ) {
			for(int i = 0,j; i < len; i++) {
				for( j = 0; j < secretKeyList.size() && buffer_read[i] != secretKeyList.get(j).original_Code; j++);
				buffer_write[i] = secretKeyList.get(j).after_Code;
			}
			out.write(buffer_write, 0, len);
		}
		
		return secretKeyList;
	}

	 /*加密文件并把密钥返回
	 * @param in 要解密的文件的输入流
	 * @param out 文件解密后的输出流
	 * @param secretKeyList 密钥
	 * */
	public static void decryptFile(InputStream in, OutputStream out, ArrayList<HFCode<Byte, Byte>> secretKeyList) throws IOException {
		byte[] buffer_read = new byte[1024];	//读的缓冲区
		byte[] buffer_write = new byte[1024];	//写的缓冲区
		int len = 0;
		while( (len = in.read(buffer_read)) != -1 ) {
			for(int i = 0, j; i < len; i++) {
				for(j = 0; j < secretKeyList.size() && buffer_read[i] != secretKeyList.get(j).after_Code; j++);
				buffer_write[i] = secretKeyList.get(j).original_Code;
			}
			out.write(buffer_write, 0, len);
		}
	}
	
	/*这个模块包含哈夫曼链表的创建,构建哈夫曼树,以及根据哈夫曼树生成密钥的方法*/
	static class HaffManModule{
		private byte leafCode;	//哈夫曼树叶子节点的编码
		
		/*根据用户传来的文件生成密钥数组并返回
		 * @param 要加密的文件的输入流
		 * return 密钥数组
		 * @see #create_HFList
		 * @see #create_HFtree
		 * @see #secretKeyList
		 * */
		public  ArrayList<HFCode<Byte, Byte>> secretKeyList(RandomAccessFile in) throws IOException{
			LinkedList<HFlistNode> hfList = create_HFList(in);	//生成哈夫曼链表
			HFtreeNode hFtreeNode = create_HFtree(hfList);		//生成哈夫曼树
			ArrayList<HFCode<Byte,Byte>> secretKeyList = create_secretKey(hFtreeNode);	//生成密钥数组
			return secretKeyList;
		}
		
		/* @param in 要加密的文件的输入流
		 * return 哈夫曼链表
		 * */
		public LinkedList<HFlistNode> create_HFList(RandomAccessFile in) throws IOException{
			if (in ==null) 
				return null;
			
			/*对输入文件的字节次数进行统计   出现多少次*/
			int[] priority = new int[256];
			int len;
			byte[] buffer = new byte[1024];
			while( (len =in.read(buffer)) != -1) {
				for(int i = 0; i < len; i++) {
					priority[ buffer[i] & 0xff ]++;
				}
			}
			
			//创建用于构建哈夫曼树的链表
			LinkedList<HFlistNode> hfList = new LinkedList<>();
			for(int i = 0; i < 256; i++) {
				if (priority[i] != 0) {
					HFtreeNode hFtreeNode = new HFtreeNode((byte) i);
					HFlistNode hFlistNode = new HFlistNode(hFtreeNode, priority[i]);
					hfList.add(hFlistNode);
				}
			}
			return hfList;
		}
		
		/*根据哈夫曼链表构建哈夫曼树
		 * @param hfList 哈夫曼链表
		 * return 哈夫曼树
		 * */
		public HFtreeNode create_HFtree(LinkedList<HFlistNode> hfList) {
			if (hfList == null) 
				return null;
			link_hfTreeNode(hfList);
			return hfList.peek().getHfNode();
		}
		
		/*把哈夫曼链表的节点消耗，只留一个节点*/
		public static void link_hfTreeNode(LinkedList<HFlistNode> hfList) {
			if (hfList == null || hfList.size() <= 1)
				return;
			
			/*获取链表最小的两个节点并移除它们*/
			HFlistNode min1 = Collections.min(hfList,HFlistNode.comparatorMin);
			HFtreeNode hfTreeNode1 = min1.getHfNode();
			hfList.remove(min1);
			HFlistNode min2 = Collections.min(hfList,HFlistNode.comparatorMin);
			HFtreeNode hfTreeNode2 = min2.getHfNode();
			hfList.remove(min2);
			
			/*创建新节点并加入到链表中*/
			int new_weight = min1.getWeight() + min2.getWeight();
			HFtreeNode new_hfTreeNode = new HFtreeNode(hfTreeNode1, hfTreeNode2);
			HFlistNode new_hfListNode = new HFlistNode(new_hfTreeNode, new_weight);
			hfList.add(new_hfListNode);
			
			link_hfTreeNode(hfList);
		}
		
		/*根据哈夫曼树创建一个用于加密解密的密钥数组
		 * @param hFtreeNode
		 * return 密钥数组
		 * */
		public ArrayList<HFCode<Byte, Byte>> create_secretKey(HFtreeNode hFtreeNode){
			if (hFtreeNode == null) 
				return null;
			
			ArrayList<HFCode<Byte, Byte>> secretKeyList = new ArrayList<>(); 
			
			link_secretKeyNode(secretKeyList,hFtreeNode);
			return secretKeyList;
		}
		
		/*先序遍历递归哈夫曼树构建密钥数组
		 *@param secretKeyList 密钥数组
		 *@param hftreeNode 哈夫曼树的当前节点
		 * */
		public void link_secretKeyNode(ArrayList<HFCode<Byte, Byte>> secretKeyList, HFtreeNode hftreeNode) {
			if (hftreeNode.left == null && hftreeNode.right == null) {//是叶子节点就停止递归
				byte original_Code = hftreeNode.getSymbol();
				byte after_Code = leafCode++;
				HFCode<Byte, Byte> hFcode = new HFCode<Byte, Byte>(original_Code, after_Code);
				secretKeyList.add(hFcode);
				return;
			}
			
			link_secretKeyNode(secretKeyList, hftreeNode.left);
			link_secretKeyNode(secretKeyList, hftreeNode.right);
		}
	}
}
