package mark.conover.crypto;

import java.util.Arrays;

public class SimplifiedDES {
	
	private static final int[] p10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
	
	private static final int[] p8 = {6, 3, 7, 4, 8, 5, 10, 9};
	
	private static final int[] p4 = {2, 4, 3, 1};
	
	/** Expand and permutate **/
	private static final int[] ep = {4, 1, 2, 3, 2, 3, 4, 1};
	
	/** Initial permutation **/
	private static final int[] ip = {2, 6, 3, 1, 4, 8, 5, 7};
	
	private static final int[] key = {0, 1, 1, 1, 1, 1, 1, 1, 0, 1};
	
	/** Substitution box 0 **/
	private static final String[][] s0 = {{"01", "00", "11", "10"},
											{"11", "10", "01", "00"},
											{"00", "10", "01", "11"},
											{"11", "01", "11", "10"}};
	
	/** Substitution box 1 **/
	private static final String[][] s1 = {{"00", "01", "10", "11"},
											{"10", "00", "01", "11"},
											{"11", "00", "01", "00"},
											{"10", "01", "00", "11"}};

	public static void main(String[] args) {
		int[] plainText = {1, 0, 1, 0, 1, 0, 0, 1};
		
		// Generate K1 and K2 round keys
		
		// P10 Permutation
		int[] tempArray = permutate(key, p10);
		
		int tempLeftHalfArrayLength = tempArray.length/2;
		int[] tempLeftHalfArray = new int[tempLeftHalfArrayLength];
		for (int i = 0; i < tempLeftHalfArrayLength; i++) {
			tempLeftHalfArray[i] = tempArray[i];
		}
		
		int tempRightHalfArrayLength = 
				tempArray.length - tempLeftHalfArrayLength;
		int[] tempRightHalfArray = new int[tempRightHalfArrayLength];
		for (int i = tempLeftHalfArrayLength; i < tempArray.length; 
				i++) {
			
			tempRightHalfArray[i] = tempArray[i];
		}
		
		// LS-1 Shift on left half bits and right half bits
		tempLeftHalfArray = shiftLeft(1, tempLeftHalfArray);
		tempRightHalfArray = shiftLeft(1, tempRightHalfArray);
		
		// Combinate left half and right half bits
		for (int i = 0; i < tempLeftHalfArrayLength; i++) {
			tempArray[i] = tempLeftHalfArray[i];
		}
		int rightHalfArrayIndex = 0;
		for (int i = tempLeftHalfArrayLength; i < tempArray.length; i++) {
			tempArray[i] = tempRightHalfArray[rightHalfArrayIndex++];
		}
		
		// P8 Permutation - minimizes from 10 bits to 8 bits
		tempArray = permutate(tempArray, p8);
		
		// Round key 1
		int[] k1 = Arrays.copyOf(tempArray, tempArray.length);
		
		// LS-2 Shift on left half bits and right half bits
		tempLeftHalfArray = shiftLeft(2, tempLeftHalfArray);
		tempRightHalfArray = shiftLeft(2, tempRightHalfArray);
		
		// Combine left half and right half bits
		for (int i = 0; i < tempLeftHalfArrayLength; i++) {
			tempArray[i] = tempLeftHalfArray[i];
		}
		rightHalfArrayIndex = 0;
		for (int i = tempLeftHalfArrayLength; i < tempArray.length; i++) {
			tempArray[i] = tempRightHalfArray[rightHalfArrayIndex++];
		}
		
		// P8 Permutation
		tempArray = permutate(tempArray, p8);
		
		// Round key 2
		int[] k2 = Arrays.copyOf(tempArray,	tempArray.length);
		
		
		// Encrypt the plaintext now that the 2 round keys were generated
		
		// Initial Permutation on plain text
		tempArray = permutate(plainText, ip);
		
		// Split the 8 bit plain text into two half arrays
		tempLeftHalfArrayLength = tempArray.length/2;
		tempLeftHalfArray = new int[tempLeftHalfArrayLength];
		for (int i = 0; i < tempLeftHalfArrayLength; i++) {
			tempLeftHalfArray[i] = tempArray[i];
		}
		
		int[] ipLeftHalfArray = Arrays.copyOf(tempLeftHalfArray, 
				tempLeftHalfArrayLength);
		
		tempRightHalfArrayLength = 
				tempArray.length - tempLeftHalfArrayLength;
		tempRightHalfArray = new int[tempRightHalfArrayLength];
		for (int i = tempLeftHalfArrayLength; i < tempArray.length; 
				i++) {
			
			tempRightHalfArray[i] = tempArray[i];
		}
		
		int[] ipRightHalfArray = Arrays.copyOf(tempRightHalfArray, 
				tempRightHalfArrayLength);
		
		// Expansion Permutation
		tempArray = permutate(tempRightHalfArray, ep);
		
		tempArray = xor(tempArray, k1);
		
		// Split the 8 bit plain text into two half arrays
		tempLeftHalfArrayLength = tempArray.length/2;
		tempLeftHalfArray = new int[tempLeftHalfArrayLength];
		for (int i = 0; i < tempLeftHalfArrayLength; i++) {
			tempLeftHalfArray[i] = tempArray[i];
		}
		
		tempRightHalfArrayLength = 
				tempArray.length - tempLeftHalfArrayLength;
		tempRightHalfArray = new int[tempRightHalfArrayLength];
		for (int i = tempLeftHalfArrayLength; i < tempArray.length; 
				i++) {
			
			tempRightHalfArray[i] = tempArray[i];
		}
		
		// S0 - Substitution box 0
		
		// row = bit1, bit4
		// column = bit2, bit3
		String row = tempLeftHalfArray[0] + "" + tempLeftHalfArray[3];
		int rowNum = getRowOrColNum(row);
		String column = tempLeftHalfArray[1] + "" + tempLeftHalfArray[2];
		int colNum = getRowOrColNum(column);
		
		String leftHalfArraySubstitution0 = s0[rowNum][colNum];	
		
		// S1 - Substitution box 1
		// row = bit1, bit4
		// column = bit2, bit3
		row = tempRightHalfArray[0] + "" + tempRightHalfArray[3];
		rowNum = getRowOrColNum(row);
		column = tempRightHalfArray[1] + "" + tempRightHalfArray[2];
		colNum = getRowOrColNum(column);
		
		String rightHalfArraySubstitution1 = s1[rowNum][colNum];	
		
		// Combine left half s0 value and right half s1 value
		tempArray = new int[4];
		tempArray[0] = Integer.parseInt(leftHalfArraySubstitution0.charAt(0) + 
				"");
		tempArray[1] = Integer.parseInt(leftHalfArraySubstitution0.charAt(1) + 
				"");
		tempArray[2] = Integer.parseInt(rightHalfArraySubstitution1.charAt(0) + 
				"");
		tempArray[3] = Integer.parseInt(rightHalfArraySubstitution1.charAt(1) + 
				"");
		
		// P4 Permutation
		tempArray = permutate(tempArray, p4);
		
		tempArray = xor(ipLeftHalfArray, tempArray);
		
		// Swap tempArray with right half of Initial Permutation array into
		// a new array
		tempArray = new int[8];
		for (int i = 0; i < ipLeftHalfArray.length; i++) {
			tempArray[i] = ipLeftHalfArray[i];
		}
		for (int i = 4; i < 8; i++) {
			tempArray[i] = ipRightHalfArray[i];
		}
		
		tempRightHalfArrayLength = 
				tempArray.length - tempLeftHalfArrayLength;
		tempRightHalfArray = new int[tempRightHalfArrayLength];
		for (int i = tempLeftHalfArrayLength; i < tempArray.length; 
				i++) {
			
			tempRightHalfArray[i] = tempArray[i];
		}
		
		// Expansion Permutation
		tempArray = permutate(tempRightHalfArray, ep);
		
		tempArray = xor(tempArray, k1);
		
		// Split the 8 bit plain text into two half arrays
		tempLeftHalfArrayLength = tempArray.length/2;
		tempLeftHalfArray = new int[tempLeftHalfArrayLength];
		for (int i = 0; i < tempLeftHalfArrayLength; i++) {
			tempLeftHalfArray[i] = tempArray[i];
		}
		
		tempRightHalfArrayLength = 
				tempArray.length - tempLeftHalfArrayLength;
		tempRightHalfArray = new int[tempRightHalfArrayLength];
		for (int i = tempLeftHalfArrayLength; i < tempArray.length; 
				i++) {
			
			tempRightHalfArray[i] = tempArray[i];
		}
		
		// S0 - Substitution box 0
		
		// row = bit1, bit4
		// column = bit2, bit3
		String row = tempLeftHalfArray[0] + "" + tempLeftHalfArray[3];
		int rowNum = getRowOrColNum(row);
		String column = tempLeftHalfArray[1] + "" + tempLeftHalfArray[2];
		int colNum = getRowOrColNum(column);
		
		String leftHalfArraySubstitution0 = s0[rowNum][colNum];	
		
		// S1 - Substitution box 1
		// row = bit1, bit4
		// column = bit2, bit3
		row = tempRightHalfArray[0] + "" + tempRightHalfArray[3];
		rowNum = getRowOrColNum(row);
		column = tempRightHalfArray[1] + "" + tempRightHalfArray[2];
		colNum = getRowOrColNum(column);
		
		String rightHalfArraySubstitution1 = s1[rowNum][colNum];	
		
	}
	
	/**
	 * Change the order (permutate) of the given tempArray indices based on the 
	 * order (permutations) specified by permuationArray.
	 * @param tempArray
	 * @param permutationArray
	 * @return integer array with the new order
	 */
	private static int[] permutate(int[] tempArray, 
			final int[] permutationArray) {
		
		int[] tempBitArray = new int[permutationArray.length];
		
		for (int i = 0; i < permutationArray.length; i++) {
			tempBitArray[i] = tempArray[permutationArray[i] - 1];
		}
		
		return tempArray;
	}
	
	/**
	 * Shift the integers in tempArray left by the amount specified.
	 * @param shiftLeftAmount
	 * @param tempArray
	 * @return integer array with the new shifted order
	 */
	private static int[] shiftLeft(int shiftLeftAmount, int[] tempArray) {
		
		int[] tempBitArray = new int[tempArray.length];
		
		int newIndex = -1;
		int lastIndex = tempArray.length - 1;
		for (int i = 0; i < tempArray.length; i++) {
			newIndex = i - shiftLeftAmount;
			
			if (newIndex < 0) {
				newIndex += lastIndex;
			}
			
			tempBitArray[newIndex] = tempArray[i];
		}
		
		return tempBitArray;
	}
	
	/**
	 * Performs a mutually exclusive bit operation between both given int
	 * arrays.
	 * @param keyArray
	 * @param tempArray
	 * @return int array generated from mutually exclusive bit operation
	 */
	private static int[] xor(int[] keyArray, int[] tempArray) {
		int[] tempBitArray = new int[keyArray.length];
		
		for (int i = 0; i < keyArray.length; i++) {
			tempBitArray[i] = tempArray[i] ^ keyArray[i];
		}
		
		return tempBitArray;
	}
	
	/**
	 * Determines the row or column number corresponding to the given String
	 * bit representation.
	 * @param rowOrColumn
	 * @return the row or column number
	 */
	private static final int getRowOrColNum(String rowOrColumn) {
		switch (rowOrColumn) {
		case "00":
			return 0;
		case "01":
			return 1;
		case "10":
			return 2;
		case "11":
			return 3;
		}
	}

}
