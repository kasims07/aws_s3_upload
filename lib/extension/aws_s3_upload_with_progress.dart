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

class AwsS3Progress {
  static final _dio = Dio(
    BaseOptions(
      connectTimeout: const Duration(seconds: 30),
      receiveTimeout: const Duration(seconds: 30),
      sendTimeout: const Duration(seconds: 30),
    ),
  );

  /// Upload a file with progress tracking, returning the file's public URL on success.
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
    void Function(double progress)? onProgress,
    CancelToken? cancelToken,
  }) async {
    var httpStr = useSSL ? 'https' : 'http';
    final endpoint = '$httpStr://$bucket.s3.$region.amazonaws.com';

    String uploadKey = key ?? (destDir.isNotEmpty ? '$destDir/${filename ?? path.basename(file.path)}' : filename ?? path.basename(file.path));

    try {
      final length = await file.length();

      // Convert metadata to AWS-compliant params
      final metadataParams = _convertMetadataToParams(metadata);

      // Generate pre-signed policy
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

      // Prepare form data
      final formData = FormData();

      // Add file with upload progress
      formData.files.add(MapEntry(
        'file',
        await MultipartFile.fromFile(
          file.path,
          filename: path.basename(file.path),
          contentType: DioMediaType.parse(contentType),
        ),
      ));

      // Add required fields
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

      // Add metadata if provided
      if (metadata != null) {
        formData.fields.addAll(metadataParams.entries.map((e) => MapEntry(e.key, e.value)));
      }

      // Make the upload request
      final response = await _dio.post(
        endpoint,
        data: formData,
        cancelToken: cancelToken,
        onSendProgress: (count, total) {
          if (onProgress != null && total != -1) {
            final progress = count / total;
            onProgress(progress);
          }
        },
        options: Options(
          headers: {
            'Accept': '*/*',
          },
          validateStatus: (status) => status == 204,
          followRedirects: false,
        ),
      );

      if (response.statusCode == 204) {
        onProgress?.call(1.0);
        return '$endpoint/$uploadKey';
      }

      throw DioException(
        requestOptions: response.requestOptions,
        error: 'Upload failed with status: ${response.statusCode}',
      );
    } on DioException catch (e) {
      debugPrint('Dio error during upload: ${e.message}');
      if (e.type == DioExceptionType.cancel) {
        debugPrint('Upload was cancelled');
      }
      rethrow;
    } catch (e) {
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
