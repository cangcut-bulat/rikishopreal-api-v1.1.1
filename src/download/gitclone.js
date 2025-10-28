const axios = require('axios');
const { Buffer } = require('buffer');

// Kelas GitHubUrlParser yang telah dikonversi dari TypeScript ke JavaScript
class GitHubUrlParser {
  constructor(options = {}) {
    this.headers = {
      "User-Agent": options.userAgent || "github-data-fetcher",
      ...(options.token && { Authorization: `token ${options.token}` }),
    };
  }

  parseUrl(url) {
    const patterns = {
      repo: /https?:\/\/github\.com\/([^/]+)\/([^/]+)(?:\/)?$/,
      file: /https?:\/\/github\.com\/([^/]+)\/([^/]+)\/blob\/([^/]+)\/(.+)/,
      raw: /https?:\/\/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/([^/]+)\/(.+)/,
      gist: /https?:\/\/gist\.github\.com\/([^/]+)\/([a-f0-9]+)/,
    };

    for (const [type, regex] of Object.entries(patterns)) {
      const match = url.match(regex);
      if (match) {
        return { type, match };
      }
    }

    throw new Error(
      "URL tidak valid. Format yang didukung: repo, file, raw, atau gist URL GitHub"
    );
  }

  async getRepoData(user, repo) {
    const apiUrl = `https://api.github.com/repos/${user}/${repo}`;
    const response = await axios.get(apiUrl, {
      headers: this.headers,
      timeout: 30000,
    });

    const {
      default_branch,
      description,
      stargazers_count,
      forks_count,
      topics,
    } = response.data;

    return {
      type: "repository",
      owner: user,
      repo: repo,
      description,
      default_branch,
      stars: stargazers_count,
      forks: forks_count,
      topics,
      download_url: `https://github.com/${user}/${repo}/archive/refs/heads/${default_branch}.zip`,
      clone_url: `https://github.com/${user}/${repo}.git`,
      api_url: apiUrl,
    };
  }

  async getFileData(user, repo, branch, path) {
    const apiUrl = `https://api.github.com/repos/${user}/${repo}/contents/${path}?ref=${branch}`;
    const response = await axios.get(apiUrl, {
      headers: this.headers,
      timeout: 30000,
    });

    return {
      type: "file",
      owner: user,
      repo: repo,
      branch,
      path,
      name: response.data.name,
      size: response.data.size,
      raw_url: response.data.download_url,
      content: Buffer.from(response.data.content, "base64").toString(),
      sha: response.data.sha,
      api_url: apiUrl,
    };
  }

  async getGistData(user, gistId) {
    const apiUrl = `https://api.github.com/gists/${gistId}`;
    const response = await axios.get(apiUrl, {
      headers: this.headers,
      timeout: 30000,
    });

    const files = Object.entries(response.data.files).map(
      ([filename, file]) => ({
        name: filename,
        language: file.language,
        raw_url: file.raw_url,
        size: file.size,
        content: file.content,
      })
    );

    return {
      type: "gist",
      owner: user,
      gist_id: gistId,
      description: response.data.description,
      files,
      created_at: response.data.created_at,
      updated_at: response.data.updated_at,
      comments: response.data.comments,
      api_url: apiUrl,
    };
  }

  async getData(url) {
    try {
      const { type, match } = this.parseUrl(url);

      switch (type) {
        case "repo":
          return await this.getRepoData(match[1], match[2]);
        case "file":
          return await this.getFileData(match[1], match[2], match[3], match[4]);
        case "gist":
          return await this.getGistData(match[1], match[2]);
        default:
          throw new Error("Format URL tidak didukung");
      }
    } catch (error) {
      throw new Error(`Error mengambil data: ${error.message}`);
    }
  }
}

async function githubScrape(url) {
  const github = new GitHubUrlParser({});
  return await github.getData(url);
}

// Integrasi dengan struktur Express Anda
module.exports = function (app) {
  app.get('/download/github', async (req, res) => {
    try {
      const { url, apikey } = req.query;

      if (!global.apikey.includes(apikey)) {
        return res.status(403).json({ status: false, error: 'Apikey invalid' });
      }

      if (!url) {
        return res.status(400).json({ status: false, error: 'Parameter url diperlukan' });
      }

      const result = await githubScrape(url.trim());
      
      res.status(200).json({
        status: true,
        creator: global.settings.creator || "Rikishopreal",
        result: result
      });

    } catch (e) {
      console.error("[GITHUB SCRAPE Error]:", e);
      res.status(500).json({
        status: false,
        creator: global.settings.creator || "Rikishopreal",
        message: "Terjadi kesalahan pada server.",
        error: e.message || e
      });
    }
  });
};

