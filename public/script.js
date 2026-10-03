const postForm = document.getElementById("postForm");
const titleInput = document.getElementById("title");
const contentInput = document.getElementById("content");
const submitButton = document.getElementById("submitButton");
const cancelButton = document.getElementById("cancelButton");
const postsContainer = document.getElementById("posts");
const loginForm = document.getElementById("loginForm");
const logoutButton = document.getElementById("logoutButton");
const registerForm = document.getElementById("registerForm");
const searchForm = document.getElementById("searchForm");
const searchInput = document.getElementById("searchInput");
const clearSearchButton = document.getElementById("clearSearchButton");

let editingPostId = null;
let posts = [];

function updateAuthUI() {
  const token = localStorage.getItem("token");

  if (token) {
    loginForm.style.display = "none";
    logoutButton.style.display = "block";
    postForm.style.display = "block";
  } else {
    loginForm.style.display = "block";
    logoutButton.style.display = "none";
    postForm.style.display = "none";
  }
}
checkAuth();

function resetPostForm() {
  editingPostId = null;
  postForm.reset();
  submitButton.textContent = "Add Post";
  cancelButton.style.display = "none";
}

async function logout() {
  try {
    await fetch("/api/logout", {
      method: "POST",
    });
  } catch (error) {
    console.error(error);
  }

  localStorage.removeItem("token");

  resetPostForm();

  document.getElementById("loginUsername").value = "";
  document.getElementById("loginPassword").value = "";

  updateAuthUI();
  getPosts();
}

logoutButton.addEventListener("click", async () => {
  await logout();

  alert("Logged out");
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const username = document.getElementById("loginUsername").value.trim();
  const password = document.getElementById("loginPassword").value;

  try {
    const response = await fetch("/api/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: username,
        password: password,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      alert(data.error);
      return;
    }

    localStorage.setItem("token", data.token);

    updateAuthUI();
    await getPosts();

    alert("Login successful");
  } catch (error) {
    console.error(error);
    alert("Something went wrong");
  }
});

registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const username = document.getElementById("registerUsername").value.trim();
  const password = document.getElementById("registerPassword").value;

  if (!username) {
    alert("Username cannot be empty");
    return;
  }

  if (username.length > 50) {
    alert("Username is too long");
    return;
  }

  if (password.length < 8) {
    alert("Password must be at least 8 characters");
    return;
  }

  try {
    const response = await fetch("/api/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: username,
        password: password,
      }),
    });
    const data = await response.json();
    if (!response.ok) {
      alert(data.error);
      return;
    }
    alert("Registered and logged in successfully");

    registerForm.reset();

    const loginResponse = await fetch("/api/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: username,
        password: password,
      }),
    });

    const loginData = await loginResponse.json();

    if (!loginResponse.ok) {
      alert(loginData.error);
      return;
    }

    localStorage.setItem("token", loginData.token);

    updateAuthUI();
    await getPosts();
  } catch (error) {
    console.error(error);
    alert("Something went wrong");
  }
});

async function refreshAccessToken() {
  try {
    const response = await fetch("/api/refresh", {
      //Browsers send HttpOnly cookies automatically with every matching HTTP request to the origin server, requiring no manual code from frontend scripts.
      method: "POST",
    });

    if (!response.ok) {
      return false;
    }

    const data = await response.json();

    localStorage.setItem("token", data.token);

    return true;
  } catch (error) {
    console.error(error);
    return false;
  }
}

async function fetchWithAuth(url, options = {}) {
  let response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      Authorization: `Bearer ${localStorage.getItem("token")}`,
    },
  });

  if (response.status !== 401 && response.status !== 403) {
    return response;
  }

  const refreshed = await refreshAccessToken();

  if (!refreshed) {
    return response;
  }

  response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      Authorization: `Bearer ${localStorage.getItem("token")}`,
    },
  });

  return response;
}

function handleAuthError(response) {
  if (response.status === 401 || response.status === 403) {
    localStorage.removeItem("token");
    resetPostForm();

    document.getElementById("loginUsername").value = "";
    document.getElementById("loginPassword").value = "";

    updateAuthUI();
    return true;
  }

  return false;
}

async function checkAuth() {
  const token = localStorage.getItem("token");

  if (!token) {
    updateAuthUI();
    return;
  }

  try {
    const response = await fetch("/api/auth/check", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (response.ok) {
      updateAuthUI();
      return;
    }

    if (response.status === 401 || response.status === 403) {
      const refreshed = await refreshAccessToken();

      if (!refreshed) {
        localStorage.removeItem("token");
      }
    }
  } catch (error) {
    console.error(error);
  }

  updateAuthUI();
}

function renderPosts(posts) {
  postsContainer.innerHTML = "";

  posts.forEach((post) => {
    const postElement = document.createElement("div");

    const titleElement = document.createElement("h2");
    titleElement.textContent = post.title;

    const contentElement = document.createElement("p");
    contentElement.textContent = post.content;

    const dateElement = document.createElement("small");
    dateElement.textContent = new Date(post.created_at).toLocaleString();

    postElement.appendChild(titleElement);
    postElement.appendChild(contentElement);
    postElement.appendChild(dateElement);

    if (localStorage.getItem("token")) {
      const editButton = document.createElement("button");
      editButton.textContent = "Edit";
      editButton.addEventListener("click", () => editPost(post.id));

      const deleteButton = document.createElement("button");
      deleteButton.textContent = "Delete";
      deleteButton.addEventListener("click", () => deletePost(post.id));

      postElement.appendChild(editButton);
      postElement.appendChild(deleteButton);
    }

    const line = document.createElement("hr");
    postElement.appendChild(line);

    postsContainer.appendChild(postElement);
  });
}

async function getPosts() {
  try {
    const response = await fetch("/api/posts");

    if (!response.ok) {
      const data = await response.json();

      alert(data.error);
      return;
    }

    posts = await response.json();

    renderPosts(posts);
  } catch (error) {
    alert("Something went wrong");
  }
}

getPosts();

async function searchPosts(search) {
  try {
    const response = await fetch(
      `/api/posts/search?search=${encodeURIComponent(search)}`
    );

    const searchResults = await response.json();

    if (!response.ok) {
      alert(searchResults.error);
      return;
    }

    renderPosts(searchResults);
  } catch (error) {
    alert("Something went wrong");
  }
}

searchForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const search = searchInput.value.trim();

  if (!search) {
    return;
  }

  await searchPosts(search);
});

clearSearchButton.addEventListener("click", async () => {
  searchInput.value = "";

  await getPosts();
});

function editPost(id) {
  if (!localStorage.getItem("token")) {
    alert("Please login first");
    return;
  }

  const post = posts.find((post) => post.id === id);

  if (!post) {
    alert("Post not found");
    return;
  }

  editingPostId = id;

  titleInput.value = post.title;
  contentInput.value = post.content;
  submitButton.textContent = "Update Post";
  cancelButton.style.display = "block";

  postForm.scrollIntoView({
    behavior: "smooth",
    block: "start",
  });
}

async function deletePost(id) {
  if (!localStorage.getItem("token")) {
    alert("Please login first");
    return;
  }
  const confirmed = confirm("Are you sure you want to delete this post?");

  if (!confirmed) {
    return;
  }

  try {
    const response = await fetchWithAuth(`/api/posts/${id}`, {
      method: "DELETE",
    });

    if (!response.ok) {
      if (handleAuthError(response)) {
        return;
      }

      const data = await response.json();
      alert(data.error);
      return;
    }

    await getPosts();
  } catch (error) {
    alert("Something went wrong");
  }
}

cancelButton.addEventListener("click", () => {
  resetPostForm();
});

postForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const data = {
    title: titleInput.value.trim(),
    content: contentInput.value.trim(),
  };

  if (!data.title || !data.content) {
    alert("Please fill in all fields");
    return;
  }

  if (data.title.length > 255) {
    alert("Title is too long");
    return;
  }

  if (editingPostId === null) {
    try {
      const response = await fetchWithAuth("/api/posts", {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
        },

        body: JSON.stringify(data),
      });

      if (!response.ok) {
        if (handleAuthError(response)) {
          return;
        }

        const data = await response.json();
        alert(data.error);
        return;
      }
    } catch (error) {
      alert("Something went wrong");
      return;
    }
  } else {
    try {
      const response = await fetchWithAuth(`/api/posts/${editingPostId}`, {
        method: "PUT",

        headers: {
          "Content-Type": "application/json",
        },

        body: JSON.stringify(data),
      });

      if (!response.ok) {
        if (handleAuthError(response)) {
          return;
        }

        const data = await response.json();
        alert(data.error);
        return;
      }

      editingPostId = null;
      submitButton.textContent = "Add Post";
    } catch (error) {
      alert("Something went wrong");
      return;
    }
  }

  postForm.reset();

  await getPosts();
});

//ts ts ts

