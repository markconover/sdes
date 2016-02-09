package mark.conover.crypto;

import java.util.Arrays;

public class SimplifiedDES {
	
	private static final int[] P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
	
	private static final int[] P8 = {6, 3, 7, 4, 8, 5, 10, 9};
	
	private static final int[] P4 = {2, 4, 3, 1};
	
	/** Expand and permutate **/
	private static final int[] EP = {4, 1, 2, 3, 2, 3, 4, 1};
	
	/** Initial permutation **/
	private static final int[] IP = {2, 6, 3, 1, 4, 8, 5, 7};
	
	/** Inverse of initial permutation **/
	private static final int[] INVERSE_IP = {4, 1, 3, 5, 7, 2, 8, 6};
	
	/** Substitution box 0 **/
	private static final String[][] S0 = {{"01", "00", "11", "10"},
											{"11", "10", "01", "00"},
											{"00", "10", "01", "11"},
											{"11", "01", "11", "10"}};
	
	/** Substitution box 1 **/
	private static final String[][] S1 = {{"00", "01", "10", "11"},
											{"10", "00", "01", "11"},
											{"11", "00", "01", "00"},
											{"10", "01", "00", "11"}};
	
	private static final boolean DEBUG_OUTPUT_ENABLED = true;

	public static void main(String[] args) {

		// Test encryption
		final int[] plainText = {0, 1, 1, 1, 0, 0, 1, 0};
		final int[] key = {1, 0, 1, 0, 0, 0, 0, 0, 1, 0};
		final int[] correctCipherText = {0, 1, 1, 1, 0, 1, 1, 1};

		int[] cipherText = encrypt(plainText, key);
		
		// Compare cipherText to correctCipherText to verify the correct
		// cipherText was generated
		boolean areEqual = Arrays.equals(cipherText, correctCipherText);	
		if (areEqual) {
			System.out.println("The correct ciphertext (" + 
					generateStringFromIntArray(correctCipherText) + ") does " +
					"equal the generated ciphertext (" + 
					generateStringFromIntArray(cipherText) + ")!");
		} else {
			System.out.println("The correct ciphertext (" + 
					generateStringFromIntArray(correctCipherText) + ") does " +
					"not equal the generated ciphertext (" + 
					generateStringFromIntArray(cipherText) + ")!");
		}
		
		// Test decryption
		int[] decryptedPlainText = decrypt(correctCipherText, key);
		
		// Compare decryptedPlainText to plainText to verify the correct
		// plaintext was decrypted
		areEqual = Arrays.equals(decryptedPlainText, plainText);	
		if (areEqual) {
			System.out.println("The correct plaintext (" + 
					generateStringFromIntArray(plainText) + ") does " +
					"equal the decrypted plaintext (" + 
					generateStringFromIntArray(decryptedPlainText) + ")!");
		} else {
			System.out.println("The correct plaintext (" + 
					generateStringFromIntArray(plainText) + ") does " +
					"not equal the decrypted plaintext (" + 
					generateStringFromIntArray(decryptedPlainText) + ")!");
		}

	}
	
	/**
	 * Decrypt the given ciphertext using Simplified DES decryption with the 
	 * given key.
	 * @param plainText
	 * @param key
	 * @return the decrypted plaintext
	 */
	public static int[] decrypt(int[] cipherText, int[] key) {
		System.out.println("Ciphertext = " + 
				generateStringFromIntArray(cipherText));
		System.out.println("Key = " + generateStringFromIntArray(key));
		
		// Generate K1 and K2 round keys
		if (DEBUG_OUTPUT_ENABLED) {
			System.out.println("Generating K1 and K2 round keys...");
		}
		
		// P10 Permutation
		int[] tempArray = permutate(key, P10);
		
		int tempLeftHalfArrayLength = tempArray.length/2;
		int[] tempLeftHalfArray = new int[tempLeftHalfArrayLength];
		for (int i = 0; i < tempLeftHalfArrayLength; i++) {
			tempLeftHalfArray[i] = tempArray[i];
		}
		
		int tempRightHalfArrayLength = 
				tempArray.length - tempLeftHalfArrayLength;
		int[] tempRightHalfArray = new int[tempRightHalfArrayLength];
		int tempIndex = 0;
		for (int i = tempLeftHalfArrayLength; i < tempArray.length; 
				i++) {
			
			tempRightHalfArray[tempIndex++] = tempArray[i];
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
		tempArray = permutate(tempArray, P8);
		
		// Round key 1
		int[] k1 = Arrays.copyOf(tempArray, tempArray.length);
		
		// LS-2 Shift on left half bits and right half bits
		tempLeftHalfArray = shiftLeft(2, tempLeftHalfArray);
		tempRightHalfArray = shiftLeft(2, tempRightHalfArray);
		
		// Combine left half and right half bits
		tempArray = new int[10];
		for (int i = 0; i < tempLeftHalfArrayLength; i++) {
			tempArray[i] = tempLeftHalfArray[i];
		}
		rightHalfArrayIndex = 0;
		for (int i = tempLeftHalfArrayLength; i < 10; i++) {
			tempArray[i] = tempRightHalfArray[rightHalfArrayIndex++];
		}
		
		// P8 Permutation
		tempArray = permutate(tempArray, P8);
		
		// Round key 2
		int[] k2 = Arrays.copyOf(tempArray,	tempArray.length);
		
		System.out.println("K1 round key = " + generateStringFromIntArray(k1));
		System.out.println("K2 round key = " + generateStringFromIntArray(k2));
		
		
		// Decrypt the ciphertext now that the 2 round keys were generated
		// and reversed
		if (DEBUG_OUTPUT_ENABLED) {
			System.out.println("Decrypting the ciphertext now...");
		}
		
		// Initial Permutation on plain text
		tempArray = permutate(cipherText, IP);
		
		// Split the 8 bit plaintext into two half arrays
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
		tempIndex = 0;
		for (int i = tempLeftHalfArrayLength; i < tempArray.length; 
				i++) {
			
			tempRightHalfArray[tempIndex++] = tempArray[i];
		}
		
		int[] ipRightHalfArray = Arrays.copyOf(tempRightHalfArray, 
				tempRightHalfArrayLength);
		
		// Expansion Permutation
		tempArray = permutate(tempRightHalfArray, EP);
		
		// Use k2 here instead of k1 for decryption
		tempArray = xor(tempArray, k2);
		
		// Split the 8 bit array into two half arrays
		tempLeftHalfArrayLength = tempArray.length/2;
		tempLeftHalfArray = new int[tempLeftHalfArrayLength];
		for (int i = 0; i < tempLeftHalfArrayLength; i++) {
			tempLeftHalfArray[i] = tempArray[i];
		}
		
		tempRightHalfArrayLength = 
				tempArray.length - tempLeftHalfArrayLength;
		tempRightHalfArray = new int[tempRightHalfArrayLength];
		tempIndex = 0;
		for (int i = tempLeftHalfArrayLength; i < tempArray.length; 
				i++) {
			
			tempRightHalfArray[tempIndex++] = tempArray[i];
		}
		
		// S0 - Substitution box 0
		
		// row = bit1, bit4
		// column = bit2, bit3
		String row = tempLeftHalfArray[0] + "" + tempLeftHalfArray[3];
		int rowNum = getRowOrColNum(row);
		String column = tempLeftHalfArray[1] + "" + tempLeftHalfArray[2];
		int colNum = getRowOrColNum(column);
		
		String leftHalfArraySubstitution0 = S0[rowNum][colNum];	
		
		// S1 - Substitution box 1
		// row = bit1, bit4
		// column = bit2, bit3
		row = tempRightHalfArray[0] + "" + tempRightHalfArray[3];
		rowNum = getRowOrColNum(row);
		column = tempRightHalfArray[1] + "" + tempRightHalfArray[2];
		colNum = getRowOrColNum(column);
		
		String rightHalfArraySubstitution1 = S1[rowNum][colNum];	
		
		// Combine the left half substitution 0 and right half substitution 1
		// arrays
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
		tempArray = permutate(tempArray, P4);
		
		tempArray = xor(ipLeftHalfArray, tempArray);
		
		// Swap tempArray with right half of Initial Permutation array into
		// a new array
		int[] swapTempArray = new int[8];
		for (int i = 0; i < ipRightHalfArray.length; i++) {
			swapTempArray[i] = ipRightHalfArray[i];
		}
		tempIndex = 4;
		for (int i = 0; i < tempArray.length; i++) {
			swapTempArray[tempIndex++] = tempArray[i];
		}
		
		if (DEBUG_OUTPUT_ENABLED) {
			System.out.println("swapTempArray after round 1 = " + 
					generateStringFromIntArray(swapTempArray));
		}
		
		// Round 2 of decryption for S-DES
		
		// Expansion Permutation
		tempArray = new int[8];
		tempRightHalfArray = new int[4];
		tempIndex = 0;
		for (int i = 4; i < 8; i++) {
			tempRightHalfArray[tempIndex++] = swapTempArray[i];
		}
		tempArray = permutate(tempRightHalfArray, EP);
		
		tempArray = xor(tempArray, k1);
		
		// Split the 8 bit array into two half arrays
		tempLeftHalfArrayLength = tempArray.length/2;
		tempLeftHalfArray = new int[tempLeftHalfArrayLength];
		for (int i = 0; i < tempLeftHalfArrayLength; i++) {
			tempLeftHalfArray[i] = tempArray[i];
		}
		
		tempRightHalfArrayLength = 
				tempArray.length - tempLeftHalfArrayLength;
		tempRightHalfArray = new int[tempRightHalfArrayLength];
		tempIndex = 0;
		for (int i = tempLeftHalfArrayLength; i < tempArray.length; 
				i++) {
			
			tempRightHalfArray[tempIndex++] = tempArray[i];
		}
		
		// S0 - Substitution box 0
		
		// row = bit1, bit4
		// column = bit2, bit3
		row = tempLeftHalfArray[0] + "" + tempLeftHalfArray[3];
		rowNum = getRowOrColNum(row);
		column = tempLeftHalfArray[1] + "" + tempLeftHalfArray[2];
		colNum = getRowOrColNum(column);
		
		leftHalfArraySubstitution0 = S0[rowNum][colNum];	
		
		// S1 - Substitution box 1
		// row = bit1, bit4
		// column = bit2, bit3
		row = tempRightHalfArray[0] + "" + tempRightHalfArray[3];
		rowNum = getRowOrColNum(row);
		column = tempRightHalfArray[1] + "" + tempRightHalfArray[2];
		colNum = getRowOrColNum(column);
		
		rightHalfArraySubstitution1 = S1[rowNum][colNum];	
		
		// Combine the left half substitution 0 and right half substitution 1
		// arrays
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
		tempArray = permutate(tempArray, P4);
		
		int[] swapTempArrayLeftHalf = new int[4];
		for (int i = 0; i < 4; i++) {
			swapTempArrayLeftHalf[i] = swapTempArray[i];
		}

		tempArray = xor(swapTempArrayLeftHalf, tempArray);
		
		// Combine array from previous xor and right half of swapTempArray
		int[] swapTempArrayRightHalf = new int[4];
		tempIndex = 0;
		for (int i = 4; i < 8; i++) {
			swapTempArrayRightHalf[tempIndex++] = swapTempArray[i];
		}
		
		int[] round2Array = new int[8];
		for (int i = 0; i < 4; i++) {
			round2Array[i] = tempArray[i];
		}
		tempIndex = 0;
		for (int i = 4; i < 8; i++) {
			round2Array[i] = swapTempArrayRightHalf[tempIndex++];
		}
		
		if (DEBUG_OUTPUT_ENABLED) {
			System.out.println("round2 array = " + 
					generateStringFromIntArray(round2Array));
		}
		
		// IP^-1 - Inverse Permutation
		tempArray = new int[8];
		tempArray = inversePermutate(round2Array);	
		
		System.out.println("Plaintext = " + generateStringFromIntArray(
				tempArray));
		
		return tempArray;
	}
	
	/**
	 * Encrypt the given plaintext using Simplified DES encryption with the
	 * given key.
	 * @param plainText
	 * @param key
	 * @return the encrypted ciphertext
	 */
	public static int[] encrypt(int[] plainText, int[] key) {
		
		System.out.println("Plaintext = " + 
				generateStringFromIntArray(plainText));
		System.out.println("Key = " + generateStringFromIntArray(key));
		
		// Generate K1 and K2 round keys
		if (DEBUG_OUTPUT_ENABLED) {
			System.out.println("Generating K1 and K2 round keys...");
		}
		
		// P10 Permutation
		int[] tempArray = permutate(key, P10);
		
		int tempLeftHalfArrayLength = tempArray.length/2;
		int[] tempLeftHalfArray = new int[tempLeftHalfArrayLength];
		for (int i = 0; i < tempLeftHalfArrayLength; i++) {
			tempLeftHalfArray[i] = tempArray[i];
		}
		
		int tempRightHalfArrayLength = 
				tempArray.length - tempLeftHalfArrayLength;
		int[] tempRightHalfArray = new int[tempRightHalfArrayLength];
		int tempIndex = 0;
		for (int i = tempLeftHalfArrayLength; i < tempArray.length; 
				i++) {
			
			tempRightHalfArray[tempIndex++] = tempArray[i];
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
		tempArray = permutate(tempArray, P8);
		
		// Round key 1
		int[] k1 = Arrays.copyOf(tempArray, tempArray.length);
		
		// LS-2 Shift on left half bits and right half bits
		tempLeftHalfArray = shiftLeft(2, tempLeftHalfArray);
		tempRightHalfArray = shiftLeft(2, tempRightHalfArray);
		
		// Combine left half and right half bits
		tempArray = new int[10];
		for (int i = 0; i < tempLeftHalfArrayLength; i++) {
			tempArray[i] = tempLeftHalfArray[i];
		}
		rightHalfArrayIndex = 0;
		for (int i = tempLeftHalfArrayLength; i < 10; i++) {
			tempArray[i] = tempRightHalfArray[rightHalfArrayIndex++];
		}
		
		// P8 Permutation
		tempArray = permutate(tempArray, P8);
		
		// Round key 2
		int[] k2 = Arrays.copyOf(tempArray,	tempArray.length);
		
		System.out.println("K1 round key = " + generateStringFromIntArray(k1));
		System.out.println("K2 round key = " + generateStringFromIntArray(k2));
		
		
		// Encrypt the plaintext now that the 2 round keys were generated
		if (DEBUG_OUTPUT_ENABLED) {
			System.out.println("Encrypting the plaintext now...");
		}
		
		// Initial Permutation on plain text
		tempArray = permutate(plainText, IP);
		
		// Split the 8 bit plaintext into two half arrays
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
		tempIndex = 0;
		for (int i = tempLeftHalfArrayLength; i < tempArray.length; 
				i++) {
			
			tempRightHalfArray[tempIndex++] = tempArray[i];
		}
		
		int[] ipRightHalfArray = Arrays.copyOf(tempRightHalfArray, 
				tempRightHalfArrayLength);
		
		// Expansion Permutation
		tempArray = permutate(tempRightHalfArray, EP);
		
		tempArray = xor(tempArray, k1);
		
		// Split the 8 bit array into two half arrays
		tempLeftHalfArrayLength = tempArray.length/2;
		tempLeftHalfArray = new int[tempLeftHalfArrayLength];
		for (int i = 0; i < tempLeftHalfArrayLength; i++) {
			tempLeftHalfArray[i] = tempArray[i];
		}
		
		tempRightHalfArrayLength = 
				tempArray.length - tempLeftHalfArrayLength;
		tempRightHalfArray = new int[tempRightHalfArrayLength];
		tempIndex = 0;
		for (int i = tempLeftHalfArrayLength; i < tempArray.length; 
				i++) {
			
			tempRightHalfArray[tempIndex++] = tempArray[i];
		}
		
		// S0 - Substitution box 0
		
		// row = bit1, bit4
		// column = bit2, bit3
		String row = tempLeftHalfArray[0] + "" + tempLeftHalfArray[3];
		int rowNum = getRowOrColNum(row);
		String column = tempLeftHalfArray[1] + "" + tempLeftHalfArray[2];
		int colNum = getRowOrColNum(column);
		
		String leftHalfArraySubstitution0 = S0[rowNum][colNum];	
		
		// S1 - Substitution box 1
		// row = bit1, bit4
		// column = bit2, bit3
		row = tempRightHalfArray[0] + "" + tempRightHalfArray[3];
		rowNum = getRowOrColNum(row);
		column = tempRightHalfArray[1] + "" + tempRightHalfArray[2];
		colNum = getRowOrColNum(column);
		
		String rightHalfArraySubstitution1 = S1[rowNum][colNum];	
		
		// Combine the left half substitution 0 and right half substitution 1
		// arrays
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
		tempArray = permutate(tempArray, P4);
		
		tempArray = xor(ipLeftHalfArray, tempArray);
		
		// Swap tempArray with right half of Initial Permutation array into
		// a new array
		int[] swapTempArray = new int[8];
		for (int i = 0; i < ipRightHalfArray.length; i++) {
			swapTempArray[i] = ipRightHalfArray[i];
		}
		tempIndex = 4;
		for (int i = 0; i < tempArray.length; i++) {
			swapTempArray[tempIndex++] = tempArray[i];
		}
		
		if (DEBUG_OUTPUT_ENABLED) {
			System.out.println("swapTempArray after round 1 = " + 
					generateStringFromIntArray(swapTempArray));
		}
		
		// Round 2 of encryption for S-DES
		
		// Expansion Permutation
		tempArray = new int[8];
		tempRightHalfArray = new int[4];
		tempIndex = 0;
		for (int i = 4; i < 8; i++) {
			tempRightHalfArray[tempIndex++] = swapTempArray[i];
		}
		tempArray = permutate(tempRightHalfArray, EP);
		
		tempArray = xor(tempArray, k2);
		
		// Split the 8 bit array into two half arrays
		tempLeftHalfArrayLength = tempArray.length/2;
		tempLeftHalfArray = new int[tempLeftHalfArrayLength];
		for (int i = 0; i < tempLeftHalfArrayLength; i++) {
			tempLeftHalfArray[i] = tempArray[i];
		}
		
		tempRightHalfArrayLength = 
				tempArray.length - tempLeftHalfArrayLength;
		tempRightHalfArray = new int[tempRightHalfArrayLength];
		tempIndex = 0;
		for (int i = tempLeftHalfArrayLength; i < tempArray.length; 
				i++) {
			
			tempRightHalfArray[tempIndex++] = tempArray[i];
		}
		
		// S0 - Substitution box 0
		
		// row = bit1, bit4
		// column = bit2, bit3
		row = tempLeftHalfArray[0] + "" + tempLeftHalfArray[3];
		rowNum = getRowOrColNum(row);
		column = tempLeftHalfArray[1] + "" + tempLeftHalfArray[2];
		colNum = getRowOrColNum(column);
		
		leftHalfArraySubstitution0 = S0[rowNum][colNum];	
		
		// S1 - Substitution box 1
		// row = bit1, bit4
		// column = bit2, bit3
		row = tempRightHalfArray[0] + "" + tempRightHalfArray[3];
		rowNum = getRowOrColNum(row);
		column = tempRightHalfArray[1] + "" + tempRightHalfArray[2];
		colNum = getRowOrColNum(column);
		
		rightHalfArraySubstitution1 = S1[rowNum][colNum];	
		
		// Combine the left half substitution 0 and right half substitution 1
		// arrays
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
		tempArray = permutate(tempArray, P4);
		
		int[] swapTempArrayLeftHalf = new int[4];
		for (int i = 0; i < 4; i++) {
			swapTempArrayLeftHalf[i] = swapTempArray[i];
		}

		tempArray = xor(swapTempArrayLeftHalf, tempArray);
		
		// Combine array from previous xor and right half of swapTempArray
		int[] swapTempArrayRightHalf = new int[4];
		tempIndex = 0;
		for (int i = 4; i < 8; i++) {
			swapTempArrayRightHalf[tempIndex++] = swapTempArray[i];
		}
		
		int[] round2Array = new int[8];
		for (int i = 0; i < 4; i++) {
			round2Array[i] = tempArray[i];
		}
		tempIndex = 0;
		for (int i = 4; i < 8; i++) {
			round2Array[i] = swapTempArrayRightHalf[tempIndex++];
		}
		
		if (DEBUG_OUTPUT_ENABLED) {
			System.out.println("round2 array = " + 
					generateStringFromIntArray(round2Array));
		}
		
		// IP^-1 - Inverse Permutation
		tempArray = new int[8];
		tempArray = inversePermutate(round2Array);	
		
		System.out.println("Ciphertext = " + generateStringFromIntArray(
				tempArray));
		
		return tempArray;
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
		
		return tempBitArray;
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
		for (int i = 0; i < tempArray.length; i++) {
			newIndex = i - shiftLeftAmount;
			
			if (newIndex < 0) {
				newIndex += tempArray.length;
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
		
		// Error code
		return -1;
	}
	
	private static final String generateStringFromIntArray(int[] tempArray) {
		StringBuilder sb = new StringBuilder();
		sb.append("{");
		for (int i = 0; i < tempArray.length; i++) {
			sb.append(String.valueOf(tempArray[i]));
			if (i != tempArray.length - 1) {
				sb.append(",");
			}
		}
		sb.append("}");
		return sb.toString();
	}
	
	/**
	 * Generate the inverse permutation of the given array.
	 * @param tempArray
	 * @return integer array resulting from the inverse permutation
	 */
	private static final int[] inversePermutate(int[] tempArray) {	
		return permutate(tempArray, INVERSE_IP);
	}

}
