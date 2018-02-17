package ecc25519

import (
	"ed25519"
	"hex"
	"crypto/rand"
	"errors"
	"strings"
)

//生成私钥公钥对
func (es *Curve) MakeKey() (err error) {
	pub,pri,err := ed25519.GenerateKey(rand.Reader)
	copy(es.key[:],pri[:])
	var _pri [32]byte;
	copy(_pri[:],pri[:32]);
	PrivateKeyToCurve25519(&es._private,&_pri);
	PublicKeyToCurve25519(&es._public,pub);
	return err;
}
//如果只需要验证签名，只要公钥就可以了，一般验证签名方也没有私钥
//pub32 必须长度大于 32，并且只取前 32 字节
func (es *Curve) SetPublic(pub32 []byte) (error) {
	if len(pub32)<32{
		return errors.New("public key length require at least 32 bytes")
	}
	copy(es.key[32:],pub32[:32]);
	var pub [32]byte;
	copy(pub[:],pub32);
	PublicKeyToCurve25519(&es._public,&pub);
	return nil;
}
func (es *Curve) GetPublic() ([]byte) {
	pub := make([]byte,32);
	copy(pub,es.key[32:]);
	return pub;
}
func (es *Curve) SetPublicString(pub string) error{
	p,err := hex.DecodeString(pub);
	if err!=nil {
		return err;
	}
	return es.SetPublic(p);
}
func (es *Curve) GetPublicString() (string) {
	return strings.ToUpper(hex.EncodeToString(es.key[32:]));
}
//如果要签名必须设置私钥，需要注意的是，还需要设置公钥，因为真正的私钥实际上是公钥私钥的组合
func (es *Curve) SetPrivate(pri32 []byte) error {
	if len(pri32)<32{
		return errors.New("private key length require at least 32 bytes")
	}
	copy(es.key[:32],pri32[:32]);
	var pri [32]byte;
	copy(pri[:],pri32[:32]);
	PrivateKeyToCurve25519(&es._private,&pri);
	return nil;
}
func (es *Curve) GetPrivate() ([]byte) {
	pri := make([]byte,32);
	copy(pri,es.key[:32]);
	return pri;
}
func (es *Curve) SetPrivateString(pri string) error {
	p,err := hex.DecodeString(pri);
	if err!=nil {
		return err;
	}
	return es.SetPrivate(p);
}
func (es *Curve) GetPrivateString() string {
	return strings.ToUpper(hex.EncodeToString(es.key[:32]));
}
func (es *Curve) GetKey() ([]byte) {
	key := make([]byte,64);
	copy(key,es.key[:]);
	return key;
}
func (es *Curve) SetKey(key []byte) error{
	if len(key)<64{
		return errors.New("key length require at least 64 bytes");
	}
	copy(es.key[:],key[:64])
	var _pri,_pub [32]byte;
	copy(_pri[:],key[:32]);
	copy(_pub[:],key[32:]);
	PrivateKeyToCurve25519(&es._private,&_pri);
	PublicKeyToCurve25519(&es._public,&_pub);
	return nil;
}
func (es *Curve) GetKeyString() (string) {
	return strings.ToUpper(hex.EncodeToString(es.key[:]));
}
func (es *Curve) SetKeyString(key string) (error) {
	k,err := hex.DecodeString(key);
	if err!=nil {
		return err;
	}
	return es.SetKey(k);
}
func (es *Curve) Sign(data []byte) (*[64]byte) {
	sign := ed25519.Sign(&es.key,data);
	return sign;
}
func (es *Curve) Verify(sign *[64]byte,data []byte) (bool) {
	var pub [32]byte;
	copy(pub[:],es.key[32:]);
	return ed25519.Verify(&pub,data,sign);
}

