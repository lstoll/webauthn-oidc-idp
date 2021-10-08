package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
)

type s3item struct {
	// Key of  the item to fetch
	Key string
	// DataFn is called with the retrieved bytes. One of this or ReaderFn should be provided. If an error is returned, the
	// fetch fails
	DataFn func([]byte) error
	// ReaderFn is called with a reader for the data. One of this or DataFn should be provided. If an error is returned, the
	// fetch fails
	ReaderFn func(r io.Reader) error
}

func fetchS3Items(ctx context.Context, s3cli s3iface.S3API, bucket string, items []s3item) error {
	var wg sync.WaitGroup
	var errs []error

	for _, s3i := range items {
		wg.Add(1)

		go func(s3i s3item) {
			defer wg.Done()

			if (s3i.DataFn == nil && s3i.ReaderFn == nil) ||
				(s3i.DataFn != nil && s3i.ReaderFn != nil) {
				errs = append(errs, fmt.Errorf("only one of either DataFn and ReaderFn must be provided"))
				return
			}

			resp, err := s3cli.GetObjectWithContext(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    &s3i.Key,
			})
			if err != nil {
				errs = append(errs, fmt.Errorf("reading %s/%s: %v", bucket, s3i.Key, err))
				return
			}
			defer resp.Body.Close()

			if s3i.DataFn != nil {
				respb, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					errs = append(errs, fmt.Errorf("reading bytes from %s/%s: %v", bucket, s3i.Key, err))
					return
				}

				if err := s3i.DataFn(respb); err != nil {
					errs = append(errs, fmt.Errorf("calling dataFn for %s/%s: %v", bucket, s3i.Key, err))
					return
				}
			}

			if s3i.ReaderFn != nil {
				if err := s3i.ReaderFn(resp.Body); err != nil {
					errs = append(errs, fmt.Errorf("calling dataFn for %s/%s: %v", bucket, s3i.Key, err))
					return
				}
			}

		}(s3i)
	}

	wg.Wait()

	if len(errs) > 0 {
		var es []string
		for _, e := range errs {
			es = append(es, e.Error())
		}
		return fmt.Errorf("fetching S3 items: %s", strings.Join(es, ", "))
	}
	return nil
}
