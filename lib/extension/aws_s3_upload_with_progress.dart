import 'dart:async';
import 'dart:io';
import 'package:amazon_cognito_identity_dart_2/sig_v4.dart';
import 'package:aws_s3_upload/enum/acl.dart';
import 'package:aws_s3_upload/src/policy.dart';
import 'package:aws_s3_upload/src/utils.dart';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:path/path.dart' as path;
import 'package:recase/recase.dart';

import 'storage_enum.dart';

class AwsS3Progress {
  AwsS3Progress._();

  static final _dio = Dio(
    BaseOptions(
      connectTimeout: const Duration(seconds: 30),
      receiveTimeout: const Duration(seconds: 30),
      sendTimeout: const Duration(hours: 4),
    ),
  );

  static Future<String?> uploadFile({
    required String accessKey,
    required String secretKey,
    required String bucket,
    required File file,
    String? key,
    String destDir = '',
    String region = 'us-east-2',
    ACL acl = ACL.public_read,
    String? filename,
    String contentType = 'binary/octet-stream',
    bool useSSL = true,
    Map<String, String>? metadata,
    required void Function(StorageTransferProgress) onProgress,
    CancelToken? cancelToken,
  }) async {
    var httpStr = useSSL ? 'https' : 'http';
    final endpoint = '$httpStr://$bucket.s3.$region.amazonaws.com';
    final length = await file.length();

    void emitProgress(StorageTransferState state, {int transferred = 0}) {
      onProgress(StorageTransferProgress(
        transferredBytes: transferred,
        totalBytes: length,
        state: state,
      ));
    }

    // Initial state
    emitProgress(StorageTransferState.inProgress);

    try {
      String uploadKey = key ?? (destDir.isNotEmpty ? '$destDir/${filename ?? path.basename(file.path)}' : filename ?? path.basename(file.path));

      final metadataParams = _convertMetadataToParams(metadata);
      final policy = Policy.fromS3PresignedPost(
        uploadKey,
        bucket,
        accessKey,
        15,
        length,
        acl,
        region: region,
        metadata: metadataParams,
      );

      final signingKey = SigV4.calculateSigningKey(secretKey, policy.datetime, region, 's3');
      final signature = SigV4.calculateSignature(signingKey, policy.encode());

      final formData = FormData();
      formData.files.add(MapEntry(
        'file',
        await MultipartFile.fromFile(
          file.path,
          filename: path.basename(file.path),
          contentType: DioMediaType.parse(contentType),
        ),
      ));

      formData.fields.addAll([
        MapEntry('key', policy.key),
        MapEntry('acl', aclToString(acl)),
        MapEntry('X-Amz-Credential', policy.credential),
        MapEntry('X-Amz-Algorithm', 'AWS4-HMAC-SHA256'),
        MapEntry('X-Amz-Date', policy.datetime),
        MapEntry('Policy', policy.encode()),
        MapEntry('X-Amz-Signature', signature),
        MapEntry('Content-Type', contentType),
      ]);

      if (metadata != null) {
        formData.fields.addAll(metadataParams.entries.map((e) => MapEntry(e.key, e.value)));
      }

      // Setup cancel token listener
      cancelToken?.whenCancel.then((_) {
        emitProgress(StorageTransferState.canceled);
      });

      final response = await _dio.post(
        endpoint,
        data: formData,
        cancelToken: cancelToken,
        onSendProgress: (count, total) {
          if (total != -1) {
            emitProgress(StorageTransferState.inProgress, transferred: count);
          }
        },
        options: Options(
          headers: {'Accept': '*/*'},
          validateStatus: (status) => status == 204,
          followRedirects: false,
        ),
      );

      if (response.statusCode == 204) {
        emitProgress(StorageTransferState.success, transferred: length);
        return '$endpoint/$uploadKey';
      }

      emitProgress(StorageTransferState.failure);
      throw DioException(
        requestOptions: response.requestOptions,
        error: 'Upload failed with status: ${response.statusCode}',
      );
    } on DioException catch (e) {
      if (e.type == DioExceptionType.cancel) {
        emitProgress(StorageTransferState.canceled);
      } else {
        emitProgress(StorageTransferState.failure);
      }
      debugPrint('Dio error during upload: ${e.message}');
      rethrow;
    } catch (e) {
      emitProgress(StorageTransferState.failure);
      debugPrint('Failed to upload to AWS: $e');
      rethrow;
    }
  }

  static Map<String, String> _convertMetadataToParams(Map<String, String>? metadata) {
    final updatedMetadata = <String, String>{};
    if (metadata != null) {
      for (var k in metadata.keys) {
        updatedMetadata['x-amz-meta-${k.paramCase}'] = metadata[k]!;
      }
    }
    return updatedMetadata;
  }
}
