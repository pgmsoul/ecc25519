# ecc25519
combine golang ed25519 and curve25519 libray in one 

ed25519 is from [https://github.com/agl/ed25519](https://github.com/agl/ed25519)

curve25519 is from [https://github.com/golang/crypto/curve25519](https://github.com/golang/crypto/curve25519)


This Libray implement ed25519 and curve25519 in same private key and public key

为了方便, 把 HEX 和一些公用包提取到当前项目里了，因为那些包可能不一定默认安装，而安装它们可能需要很长时间

```
package main

import(
	"hex"
	"strings"
	"fmt"
	"ecc25519"
)

func main() {
	CreateKey();
	DataSign()
	DataCrypt();

	SetExistKey();
	DataSign()
	DataCrypt();
}


var curve ecc25519.Curve;
var src string = "You can always define a function in Go to do what you want, than assign the function to console.log in javascript.";
var srcdata []byte;

func CreateKey()  {
	fmt.Println("create a new pair key")
	curve.MakeKey();
	fmt.Println("private key(32 bytes):",curve.GetPrivateString());
	curve.GetPublicString();
	fmt.Println("public key(32 bytes):",curve.GetPublicString());
}
func SetExistKey()  {
	//set a exist key for curve
	keys := "0824E6110F5E0BD6500855C4CF48BD15BB435175D34DC472BED58605634BDD7BDE0C2B412AB884AB9678791CF043ACD8A55F8DC5488A84C7B94E731F7F206D32"
	curve.SetKeyString(keys);
}
func DataSign() {
	//sign and verfy
	sign := curve.Sign(srcdata);
	if(curve.Verify(sign,srcdata)){
		fmt.Println("verify success")
	}else{
		fmt.Println("verify failed")
	}
	//modify sign data
	sign[20] = 3;
	if(curve.Verify(sign,srcdata)){
		fmt.Println("verify success")
	}else{
		fmt.Println("verify failed")
	}
}

func DataCrypt()  {
	srcdata = []byte(src);
	//encrypt data length at most 64 bytes
	var data []byte;
	if len(srcdata)>64 {
		data = srcdata[:64]
	}else{
		data = srcdata;
	}
	//begin encrypt
	enc,err := curve.Encrypt(data)
	if err!=nil{
		fmt.Println(err);
		return;
	}
	//print ciphertext to hex
	PrintHex("ciphertext:",enc);
	//begin decrypt
	dec,err := curve.Decrypt(enc)
	if err!=nil{
		fmt.Println(err);
	}
	//print plaintext
	fmt.Println("plaintext:",string(dec));
}
func PrintHex(flag string,data []byte)  {
	hex := hex.EncodeToString(data);
	hex = strings.ToUpper(hex);
	fmt.Println(flag,hex);
}
```
