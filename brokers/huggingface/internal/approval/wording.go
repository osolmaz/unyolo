package approval

var operationTexts = map[string]string{
	"repo.create":          "create a Hugging Face repository",
	"repo.contents.read":   "read repository contents",
	"git.fetch":            "fetch from a Git repository",
	"git.push.append":      "append to Git history",
	"git.push.force":       "rewrite Git history",
	"git.ref.delete":       "delete a Git reference",
	"git.tag.update":       "move or delete a Git tag",
	"bucket.object.read":   "read a bucket object",
	"bucket.object.write":  "write a bucket object",
	"bucket.object.delete": "delete a bucket object",
}

func operationText(operation string) string {
	if text, ok := operationTexts[operation]; ok {
		return text
	}
	return operation
}
