import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import GroupItem from "./GroupItem";
import { useEffect } from "react";
import axios from "axios";

const Container = styled.div`
  position: relative;
  max-width: 375px;
  height: 740px;
  background: #fff;
  border: 1px solid gray;
  margin: 30px auto;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;

  @media screen and (max-width: 768px) {
    width: 100%;
    padding-left: 0rem;
    padding-right: 0rem;
  }
`;

const BluePoint = styled.div`
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  color: white;
  width: 100%;
`;

const Mark = styled.div`
  position: relative;
  margin-top: -190px;
  left: -150px;
`;
const StickyBox = styled.div`
  position: sticky;
  top: 0;
`;
const BoxZone = styled.div`
  position: relative;
  max-width: 346px;
  height: 600px;
  margin: auto;
  top: -30px;
  overflow-y: scroll;
  overflow-x: hidden;
  &::-webkit-scrollbar {
    /* WebKit 브라우저의 스크롤바를 숨김 */
    width: 0;
    background: transparent;
  }
`;
const AddBox = styled.div`
  position: relative;
  margin: auto;
  width: 340px;
  height: 175px;
  margin-bottom: 10px;
  border-radius: 17.76px;
  border: 2px dashed #0057ff;
  display: flex;
  flex-direction: column;
  align-items: center;
`;
const LogoutBtn = styled.div`
  position: relative;
  color: #fff;
  text-align: center;
  font-family: Inter;
  font-size: 13px;
  font-style: normal;
  font-weight: 400;
  line-height: 17px; /* 141.667% */
  letter-spacing: -0.5px;
  margin-bottom: 50px;
  margin-top: -45px;
  left: 130px;
`;

const Home = () => {
  const navigate = useNavigate();

  const gotoAdd = () => {
    navigate("/Membership4");
  };
  const logoutfunc = () => {
    // 로그아웃 부분 추가..
    const token = localStorage.getItem("token");
    const headers = { Authorization: `Token ${token}` };
    try {
      axios.post(`http://127.0.0.1:8000/api/logout/`, {
        headers,
      });
      localStorage.removeItem("token");
      navigate("/"); // 로그인하면 페이지 이동
    } catch (error) {
      console.error("로그인 실패:", error);
    }
  };
  // 그룹 가져오는 부분
  const [postList, setPostList] = useState([]);
  const [loading, setLoading] = useState(false); // f로딩 상태

  // 토큰 추가
  useEffect(() => {
    const token = localStorage.getItem("token");
    const headers = { Authorization: `Token ${token}` };
    const fetchData = async () => {
      setLoading(true);
      try {
        // API 호출
        const response = await axios.get(`http://127.0.0.1:8000/group/`, {
          headers,
        });
        setPostList(response.data); // API 응답으로 받은 데이터를 state에 저장
      } catch (error) {
        console.error("Error fetching data:", error);
      }
      setLoading(false); // 로딩 상태 변경
    };
    fetchData();
  }, []);
  if (loading) {
    return <div>대기중...</div>;
  }

  return (
    <Container>
      <StickyBox>
        <BluePoint>
          <img
            style={{ width: "100%", height: "100%", objectFit: "cover" }}
            src={`${process.env.PUBLIC_URL}/images/bluepoint.svg`}
          />
          <Mark>
            <img src={`${process.env.PUBLIC_URL}/images/heartmark.svg`} />
          </Mark>
          <LogoutBtn onClick={logoutfunc}>로그아웃</LogoutBtn>
        </BluePoint>
      </StickyBox>
      <BoxZone>
        {/* 사용자의 그룹 전체 리스트들 위에 불러오고.. 여기다간 GroupItem반복문 써서 돌리기
        -> 돌릴 때 props로 그룹 코드 전달 해야함 */}
        {postList.map((e) => (
          <GroupItem key={e.code} code={e.code} />
        ))}
        <AddBox onClick={gotoAdd}>
          <img
            style={{ margin: "40px" }}
            src={`${process.env.PUBLIC_URL}/images/addbox2.svg`}
          />
        </AddBox>
      </BoxZone>
    </Container>
  );
};

export default Home;
