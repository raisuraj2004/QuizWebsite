ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';
ALTER TABLE quizzes ADD COLUMN description TEXT DEFAULT '';
ALTER TABLE quizzes ADD COLUMN quiz_code TEXT;
ALTER TABLE quizzes ADD COLUMN status TEXT DEFAULT 'draft';
ALTER TABLE quizzes ADD COLUMN deleted_at TIMESTAMP NULL;

UPDATE quizzes
SET status = 'draft'
WHERE status IS NULL OR status NOT IN ('draft', 'published');
