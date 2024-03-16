## What is ARSA?

​	**ARSA** is a **cross-platform RSA encryption and signature library**. The key and text exported can be circulated in all languages that ARSA supports.

​	Most importantly, it is incredibly easy to master with a handful of actual code.

## What can ARSA do?

- ***Do standard RSA encryption and signature***
- ***Encrypt long texts***
- ***Cross platform***
- ***One single unified format in all languages***

## Catalogue

1. [Download and import](#download_and_import)
2. [Create new ARSA keys](#create_new_arsa_keys)
3. [Import existed keys](#import_existed_keys)
4. [Export keys to Strings](#export_keys_to_strings)
5. [Encrypt](#encrypt)
6. [Decrypt](#decrypt)
7. [Make signatures](#make_signatures)
8. [Verify signatures](#verify_signatures)
9. [Key objects conversion](#key_objects_conversion)

## How to use?

1. ### <span id="download_and_import">Download and import</span>

   #### *JAVA* 

   Download the source code (.java) [here](https://github.com/ATATC/ARSA/releases/) or install it through Maven Central:

   ##### Gradle

   ```groovy
   dependencies {
       implmentation 'com.atatctech:arsa:2.0.0'
   }
   ```

   ##### Maven

   ```xml
   <dependency>
       <groupId>com.atatctech</groupId>
       <artifactId>arsa</artifactId>
       <version>2.0.0</version>
   </dependency>
   ```

   Then import:

   ```java
   import com.atatctech.arsa.ARSA;
   ```

   #### *Python 3+*

   Download the source code (.py) [here](https://github.com/ATATC/ARSA/releases/) or install it through Pip:

   #### *Windows*

   ```powershell
   pip install arsa
   ```

   #### *Linux*

   ```shell
   pip3 install arsa
   ```

   Then import:

   ```python
   from arsa import *
   ```

2. ### <span id="create_new_arsa_keys">Create new ARSA keys</span>

   #### *JAVA*

   ```java
   int keyLength;	// RSA key length, 2048 recommended
   ARSA.AKeyPair keyPair = ARSA.newkeys(keyLength);
   ```

   ##### Get the public key:

   ```java
   ARSA.APublicKey publicKey = keyPair.getPublicKey();
   ```

   ##### Get the private key:

   ```java
   ARSA.APrivateKey privateKey = keyPair.getPrivateKey();
   ```

   #### *Python 3+*

   ```python
   key_pair = new_keys()
   ```

   or

   ```python
   key_length: int	# RSA key length, 2048 in default
   key_pair = new_keys(key_length)
   ```

   ##### Get the public key:

   ```python
   public_key: APublicKey = key_pair.get_public_key()
   ```

   ##### Get the private key:

   ```python
   private_key: APrivateKey = key_pair.get_private_key()
   ```

3. ### <span id="import_existed_keys">Import existed keys</span>

   1. ### Public keys

      #### *JAVA*

      ```java
      String publicKeyString;
      int keyLength;
      ARSA.APublicKey publicKey = ARSA.APublicKey.importPublicKey(publicKeyString, keyLength);
      ```

      Or from `java.security.PublicKey`:

      ```java
      PublicKey publicKeyObject;
      int keyLength;
      ARSA.APublicKey publicKey = ARSA.APublicKey.importPublicKey(publicKeyObject, keyLength);
      ```

      #### *Python 3+*

      ```python
      public_key_bytes: bytes
      key_length: int
      APublicKey public_key = APublicKey.import_public_key(public_key_bytes, key_length)
      ```

   2. ### Private keys

      Just change every "public" above to "private".

4. ### <span id="export_keys_to_strings">Export keys to Strings</span>

   1. ### Public keys

      #### *JAVA*

      ```java
      ARSA.APublicKey publicKey;
      String publicKeyString = publicKey.toString();
      ```

      #### *Python 3+*

      ```python
      public_key: APublicKey
      public_key_string: str = str(public_key)
      ```

   2. ### Private keys

      Just change every "public" above to "private".

5. ### <span id="encrypt">Encrypt</span>

   #### *JAVA*

   ```java
   ARSA.APublicKey publicKey;
   String plainText;
   String cipherText = ARSA.encrypt(plainText, publicKey);
   ```

   #### *Python 3+*

   ```python
   public_key: APublicKey
   plain_text: str
   cipher_text: bytes = encrypt(plain_text, public_key);
   ```

6. ### <span id="decrypt">Decrypt</span>

   #### *JAVA*

   ```java
   ARSA.APrivateKey privateKey;
   String cipherText;
   String plainText = ARSA.decrypt(cipherText, privateKey);
   ```

   #### *Python 3+*

   ```python
   private_key: APrivateKey
   cipher_text: base64.bytes_types
   plain_text: str = decrypt(cipher_text, private_key)
   ```

7. ### <span id="make_signatures">Make signatures</span>

   #### *JAVA*

   ```java
   String content;
   ARSA.APrivateKey privateKey;
   String signature = ARSA.sign(content, privateKey);
   ```

   #### *Python 3+*

   ```python
   content: base64.bytes_types
   private_key: APrivateKey
   signature: bytes = sign(content, private_key)
   ```

8. ### <span id="verify_signatures">Verify signatures</span>

   #### *JAVA*

   ```java
   String content;
   String signature;
   ARSA.APublicKey publicKey;
   boolean isQualified = ARSA.verify(content, signature, publicKey);
   ```

   #### *Python 3+*

   ```python
   content: base64.bytes_types
   signature: bytes
   public_key: APublicKey
   bool is_qualified = verify(content, signature, public_key)
   ```

9. ### <span id="key_objects_conversion">Key objects conversion</span>

   1. #### *JAVA*

      ##### To `java.security.PublicKey`:

      ```java
      APublicKey publicKey;
      PublicKey publicKeyObject = publicKey.getPublicKey();
      ```

      ##### To `java.security.PrivateKey`:

      ```java
      APrivateKey privateKey;
      PrivateKey privateKeyObject = privateKey.getPrivateKey();
      ```

   2. #### *Python 3+*

      ##### To `Crypto.PublicKey.RSA.PublicKey`:

      ```python
      public_key: APublicKey
      public_key_object: PublicKey = public_key.get_public_key()
      ```

      ##### To `Crypto.PublicKey.RSA.RsaKey`:

      ```python
      private_key: APrivateKey
      private_key_object: RsaKey = private_key.get_private_key()
      ```

