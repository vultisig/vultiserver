package storage

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/sirupsen/logrus"

	"github.com/vultisig/vultiserver/config"
)

type BlockStorage struct {
	cfg      config.Config
	session  *session.Session
	s3Client *s3.S3
	logger   *logrus.Logger
}

func NewBlockStorage(cfg config.Config) (*BlockStorage, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:           aws.String(cfg.BlockStorage.Region),
		Endpoint:         aws.String(cfg.BlockStorage.Host),
		Credentials:      credentials.NewStaticCredentials(cfg.BlockStorage.AccessKey, cfg.BlockStorage.SecretKey, ""),
		S3ForcePathStyle: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	return &BlockStorage{
		cfg:      cfg,
		session:  sess,
		s3Client: s3.New(sess),
		logger:   logrus.WithField("module", "block_storage").Logger,
	}, nil
}

func (bs *BlockStorage) FileExist(fileName string) (bool, error) {
	_, err := bs.s3Client.HeadObject(&s3.HeadObjectInput{
		Bucket: aws.String(bs.cfg.BlockStorage.Bucket),
		Key:    aws.String(fileName),
	})
	if err != nil {
		bs.logger.Error(err)
		filePathName := filepath.Join(bs.cfg.Server.VaultsFilePath, fileName)
		_, err := os.Stat(filePathName)
		return false, err
	}
	return true, nil
}
func (bs *BlockStorage) UploadFileWithRetry(fileContent []byte, fileName string, retry int) error {
	var err error
	for i := 0; i < retry; i++ {
		err = bs.UploadFile(fileContent, fileName)
		if err == nil {
			return nil
		}
		bs.logger.Error(err)
	}
	return err
}
func (bs *BlockStorage) UploadFile(fileContent []byte, fileName string) error {
	bs.logger.Infoln("upload file", fileName, "bucket", bs.cfg.BlockStorage.Bucket, "content length", len(fileContent))
	output, err := bs.s3Client.PutObjectWithContext(context.TODO(), &s3.PutObjectInput{
		Bucket:        aws.String(bs.cfg.BlockStorage.Bucket),
		Key:           aws.String(fileName),
		Body:          aws.ReadSeekCloser(bytes.NewReader(fileContent)),
		ContentLength: aws.Int64(int64(len(fileContent))),
	})
	if err != nil {
		bs.logger.Error(err)
		return err
	}
	if output != nil {
		bs.logger.Infof("upload file %s success, version id: %s", fileName, aws.StringValue(output.VersionId))
	}
	return nil
}

func (bs *BlockStorage) GetFile(fileName string) ([]byte, error) {
	bs.logger.Infoln("get file", fileName, "bucket", bs.cfg.BlockStorage.Bucket)
	output, err := bs.s3Client.GetObjectWithContext(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bs.cfg.BlockStorage.Bucket),
		Key:    aws.String(fileName),
	})
	if err != nil {
		bs.logger.Error(err)
		return nil, err
	}
	defer func() {
		if err := output.Body.Close(); err != nil {
			bs.logger.Error(err)
		}
	}()
	return io.ReadAll(output.Body)
}
func (bs *BlockStorage) DeleteFile(fileName string) error {
	_, err := bs.s3Client.DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(bs.cfg.BlockStorage.Bucket),
		Key:    aws.String(fileName),
	})
	if err != nil {
		bs.logger.Error(err)
		return err
	}
	bs.logger.Infof("delete file %s success", fileName)
	return nil
}
