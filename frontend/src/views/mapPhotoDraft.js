export function createMapPhotoDrafts(marker) {
  if (!marker) return []

  const urls = Array.isArray(marker.photos) && marker.photos.length
    ? marker.photos
    : marker.photo_url
      ? [marker.photo_url]
      : []

  return urls
    .filter(Boolean)
    .map((url) => ({ url, file: null }))
}

export function createPendingPhotoDrafts(files, createObjectURL = (file) => URL.createObjectURL(file)) {
  return Array.from(files, (file) => ({
    url: createObjectURL(file),
    file,
  }))
}

export function revokeLocalPhotoDrafts(drafts, revokeObjectURL = (url) => URL.revokeObjectURL(url)) {
  for (const draft of drafts) {
    if (draft?.file && draft.url) {
      revokeObjectURL(draft.url)
    }
  }
}

export async function resolveMapPhotoDraftUrls(drafts, uploadPhoto, cleanupUploaded = async () => {}) {
  const urls = []
  const uploadedNames = []

  try {
    for (const draft of drafts) {
      if (!draft?.file) {
        if (draft?.url) {
          urls.push(draft.url)
        }
        continue
      }

      const result = await uploadPhoto(draft.file, draft.file.name)
      if (!result?.ok || !result.url || !result.name) {
        throw new Error('upload failed')
      }

      uploadedNames.push(result.name)
      urls.push(result.url)
    }

    return { urls, uploadedNames }
  } catch (error) {
    if (uploadedNames.length) {
      try {
        await cleanupUploaded(uploadedNames)
      } catch {
        // 清理失败不覆盖原始上传错误
      }
    }
    throw error
  }
}
