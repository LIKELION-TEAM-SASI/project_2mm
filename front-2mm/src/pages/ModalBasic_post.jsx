// Modal_post.jsx
import React from "react";
import PropTypes from "prop-types";
import styles from "./ModalBasic_post.module.css";
import { useNavigate } from "react-router-dom";
import axios from "axios";
const BACKEND_URL =
  "https://uuju.pythonanywhere.com" || "http://127.0.0.1:8000";

function ModalBasic({ setModalOpen, postId, groupCode, setPosts }) {
  const navigate = useNavigate();
  const code = localStorage.getItem("code");

  // Post4 페이지로 이동하는 함수, postId와 groupCode 전달
  const btnPost4 = () => {
    navigate(`/Post4/${postId}/${code}`); // Post4 페이지로 이동하면서 postId와 code 전달
  };

  // 모달 끄기
  const closeModal = () => {
    setModalOpen(false);
  };

  // 게시글 삭제
  const onDeletePost = async () => {
    try {
      const token = localStorage.getItem("token");
      const code = localStorage.getItem("code");
      console.log(token);
      console.log(code);
      console.log(postId);

      const response = await axios.delete(
        `${BACKEND_URL}/group/${code}/posts/${postId}/`,
        {
          headers: {
            Authorization: `Token ${token}`, // Use "Bearer" prefix
            "Content-Type": "application/json",
          },
        }
      );

      if (response.status === 204) {
        closeModal(); // 삭제 성공 시 모달 닫기

        // 삭제된 게시글의 ID를 기반으로 업데이트된 게시글 목록을 생성
        setPosts((prevPosts) => prevPosts.filter((post) => post.id !== postId));

        navigate("/Post1"); // 삭제 후 포스트 목록 페이지로 이동
      } else {
        console.error(
          "Failed to delete post. Response status:",
          response.status
        );
      }
    } catch (error) {
      console.error("Error deleting post:", error);
    }
  };

  return (
    <div className={styles.container}>
      <img
        className={styles.rewrite}
        src={`${BACKEND_URL}/images/rewrite.svg`}
        alt="rewrite"
        onClick={btnPost4} // Post4 페이지로 이동하는 함수 호출
      />
      <img
        className={styles.delete}
        src={`${BACKEND_URL}/images/delete.svg`}
        alt="delete"
        onClick={onDeletePost} // 게시글 삭제 처리 함수 호출
      />
      <img
        className={styles.cancel}
        src={`${BACKEND_URL}/images/cancel.svg`}
        alt="cancel"
        onClick={closeModal} // 모달 닫기
      />
    </div>
  );
}

ModalBasic.propTypes = {
  setModalOpen: PropTypes.func.isRequired,
  postId: PropTypes.number.isRequired,
  groupCode: PropTypes.string.isRequired,
  setPosts: PropTypes.func.isRequired, // setPosts 함수도 전달 받아야 함
};

export default ModalBasic;
